from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vuln_atlas import db as dbm  # noqa: E402
from vuln_atlas.card import Card  # noqa: E402
from vuln_atlas.rank import build_query, search  # noqa: E402
from vuln_atlas.router import parse_request  # noqa: E402
from vuln_atlas.version import any_match, matches  # noqa: E402


def _card(cid: str, **kw) -> Card:
    body = kw.pop(
        "body",
        "## 目标特征 / 版本\n\ntest product <= 1.0\n\n"
        "## 前置条件\n\nnone\n\n"
        "## 最小步骤\n\n1. curl http://TARGET/x\n\n"
        "## 预期 marker\n\nroot:x:0:0\n\n"
        "## 证据指针\n\nartifacts/{0}/a.txt\n\n"
        "## 失败模式 / 不适用条件\n\nfixed in 1.1\n".format(cid),
    )
    return Card(id=cid, cve=cid if cid.startswith("CVE-") else None, title=kw.pop("title", f"test {cid}"),
                body=body, **kw)


@pytest.fixture()
def conn(tmp_path):
    c = dbm.connect(tmp_path / "index.db")
    dbm.init_db(c)
    dbm.upsert_card(c, _card(
        "CVE-2018-3760",
        title="Rails Sprockets path traversal",
        product="sprockets",
        versions=["<= 3.7.1"],
        fingerprint=["X-Runtime", "/assets/"],
        tags=["lfi", "path-traversal"],
        attack_surface=["http"],
        poc_type="curl",
        poc_code="curl -sS --path-as-is 'http://TARGET/assets/file:%2f%2f/etc/passwd'",
        confidence="verified",
        last_verified="2026-11-01",
        aliases=["rails sprockets lfi"],
    ))
    dbm.upsert_card(c, _card(
        "CVE-2021-44228",
        title="Log4j2 JNDI RCE",
        product="log4j",
        versions=["<= 2.14.1"],
        tags=["rce", "jndi"],
        attack_surface=["http"],
        confidence="verified",
    ))
    dbm.upsert_card(c, _card(
        "CVE-2016-0095",
        title="windows_10 CVE-2016-0095",
        product="windows_10",
        tags=["info-leak"],
        confidence="unverified",
    ))
    c.commit()
    yield c
    c.close()


# --- 回归：rank.search 的 CVE 回退分支在普通 cursor 上崩 ---

def test_search_cve_fallback_survives_tuple_rows(conn):
    """cve 精确查不到、id 回退命中时，连接没开 row_factory 也不能崩。"""
    raw = sqlite3.connect(conn.execute("PRAGMA database_list").fetchone()[2])
    try:
        raw.execute("SELECT 1").fetchone()
        assert type(raw.execute("SELECT 1").fetchone()) is tuple
        res = search(raw, build_query(cve="CVE-2018-3760"), top_k=5)
    finally:
        raw.close()
    assert [r["id"] for r in res["results"]] == ["CVE-2018-3760"]
    assert "cve_exact" in res["results"][0]["why"]


def test_search_results_are_plain_dicts(conn):
    res = search(conn, build_query(cve="CVE-2018-3760"), top_k=5)
    payload = json.dumps(res, ensure_ascii=False)
    assert json.loads(payload)["results"][0]["id"] == "CVE-2018-3760"


# --- 检索行为 ---

def test_product_version_match(conn):
    res = search(conn, build_query(product="log4j", version="2.10.0"), top_k=5)
    ids = [r["id"] for r in res["results"]]
    assert ids and ids[0] == "CVE-2021-44228"
    assert "version_match" in res["results"][0]["why"]


def test_version_out_of_range_filtered(conn):
    res = search(conn, build_query(product="log4j", version="2.17.1"), top_k=5)
    assert "CVE-2021-44228" not in [r["id"] for r in res["results"]]


def test_request_fingerprint_routing(conn):
    req = "GET /assets/file HTTP/1.1\nHost: TARGET\nX-Runtime: 0.02"
    q = build_query(request=req)
    assert q.fingerprint
    res = search(conn, q, top_k=5)
    assert res["results"] and res["results"][0]["id"] == "CVE-2018-3760"


def test_cjk_concept_expansion(conn):
    q = build_query(query="Rails本地文件包含怎么打")
    res = search(conn, q, top_k=5)
    assert "CVE-2018-3760" in [r["id"] for r in res["results"]]


def test_empty_query_returns_suggestions(conn):
    res = search(conn, build_query(query="完全不存在的东西 zzzqqq"), top_k=5)
    assert res["results"] == []
    assert "suggested_queries" in res


# --- 组件级 ---

@pytest.mark.parametrize("version,expr,expected", [
    ("2.10.0", ">= 2.0.0-beta9, <= 2.14.1", True),
    ("2.15.0", ">= 2.0.0-beta9, <= 2.14.1", False),
    ("9.0.20", "9.0", True),
    ("3.7.1", "<= 3.7.1", True),
])
def test_version_matches(version, expr, expected):
    assert matches(version, expr) is expected


def test_any_match_unknown_version():
    assert any_match(None, ["<= 1.0"]) is None
    assert any_match("0.9", []) is None


def test_parse_request_extracts_fields():
    parsed = parse_request(
        "GET /api/v1 HTTP/1.1\nHost: 10.0.0.1\nServer: Apache-Coyote/1.1\nX-Powered-By: Spring"
    )
    assert parsed["attack_surface"] == ["http"]
    flat = json.dumps(parsed, ensure_ascii=False).lower()
    assert "spring" in flat or "coyote" in flat


def test_upsert_is_idempotent(conn):
    before = conn.execute("SELECT count(*) FROM cards").fetchone()[0]
    dbm.upsert_card(conn, _card("CVE-2021-44228", title="Log4j2 JNDI RCE", product="log4j", tags=["rce"]))
    after = conn.execute("SELECT count(*) FROM cards").fetchone()[0]
    assert before == after
    terms = conn.execute(
        "SELECT term FROM card_terms WHERE card_id='CVE-2021-44228' AND kind='tag'"
    ).fetchall()
    assert [r["term"] for r in terms] == ["rce"]


def test_get_card_by_cve_alias(conn):
    assert dbm.get_card(conn, "CVE-2018-3760").id == "CVE-2018-3760"


# --- 入口 ---

def test_entrypoints_run(tmp_path):
    for name in ("cli.py", "mcp_server.py", "web_app.py"):
        assert (ROOT / name).is_file(), name
    out = subprocess.run(
        [sys.executable, "-c", "import vuln_atlas, vuln_atlas.cli, vuln_atlas.mcp_server, vuln_atlas.rank, vuln_atlas.router"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert out.returncode == 0, out.stderr


def test_mcp_tools_list(tmp_path):
    lines = "\n".join([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ])
    out = subprocess.run(
        [sys.executable, str(ROOT / "mcp_server.py")],
        input=lines + "\n", capture_output=True, text=True, timeout=60,
        env={**__import__("os").environ, "VULN_ATLAS_DB": str(tmp_path / "nope.db")},
    )
    names = set()
    for line in out.stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        for tool in (msg.get("result") or {}).get("tools") or []:
            names.add(tool["name"])
    assert {"wiki_search", "wiki_get"} <= names, out.stdout + out.stderr
