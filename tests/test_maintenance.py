from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vuln_atlas import db as dbm  # noqa: E402
from vuln_atlas.card import Card, derive_title, is_generic_title, render_card  # noqa: E402
from vuln_atlas.rank import BUILTIN_CONCEPTS, build_query, expand_concepts, search  # noqa: E402


def _body(cid: str, ident: str, steps: str = "1. curl http://TARGET/x") -> str:
    return (
        f"## 目标特征 / 版本\n\ntest 版本 未标注；指纹：x。{ident}\n\n"
        f"## 前置条件\n\nnone\n\n"
        f"## 最小步骤\n\n{steps}\n\n"
        f"## 预期 marker\n\nroot:x:0:0\n\n"
        f"## 证据指针\n\n本地证据：无（仅元数据卡）\n\n"
        f"## 失败模式 / 不适用条件\n\nfixed in 1.1\n"
    )


def _card(cid: str, **kw) -> Card:
    steps = kw.pop("steps", "1. curl http://TARGET/x")
    body = kw.pop("body", _body(cid, kw.pop("ident", "test vulnerability description"), steps))
    return Card(id=cid, cve=cid if cid.startswith("CVE-") else None,
                title=kw.pop("title", f"test {cid}"), body=body, **kw)


@pytest.fixture()
def conn(tmp_path):
    c = dbm.connect(tmp_path / "index.db")
    dbm.init_db(c)
    yield c
    c.close()


# ---------- 标题 ----------

def test_derive_title_from_generic():
    t = derive_title(
        "windows_10 CVE-2016-0095",
        "The kernel-mode driver in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1 allows local users to gain privileges.",
        product="windows_10",
    )
    assert "CVE-2016" not in t
    assert t.lower().startswith("kernel-mode driver")
    assert len(t) <= 160


def test_derive_title_keeps_descriptive_title():
    original = "Rails Sprockets 二次解码路径穿越（任意文件读取）"
    assert derive_title(original, "some description") == original


def test_derive_title_strips_prefix_and_enrichment():
    t = derive_title(
        "tomcat CVE-2020-9484",
        "In Apache Tomcat 9.0.0 to 9.0.30, a deserialization flaw exists.（KEV 已知被利用; EPSS 0.900）",
        product="tomcat",
    )
    assert not t.startswith("In ")
    assert "EPSS" not in t and "KEV" not in t
    assert "Apache Tomcat" in t


@pytest.mark.parametrize("lead", ["a ", "an ", "this ", "there is a "])
def test_derive_title_strips_indefinite_lead(lead):
    t = derive_title(
        "tomcat CVE-2020-9484",
        f"{lead}deserialization flaw exists in Apache Tomcat 9.0.",
        product="tomcat",
    )
    assert t.lower().startswith("deserialization flaw")


def test_retitle_strips_article_from_exported_cards(tmp_path):
    """存量卡也要吃到冠词剥离：repair 之后再导出，标题不能以 'a ' 开头。"""
    from vuln_atlas.maintenance import repair

    db = dbm.connect(tmp_path / "index.db")
    dbm.init_db(db)
    card = _card("CVE-2019-5418", title="rails CVE-2019-5418", product="rails",
                 ident="a File Content Disclosure vulnerability in Action View")
    dbm.upsert_card(db, card)
    db.commit()
    cards_dir = tmp_path / "cards"
    repair(db, cards_dir=cards_dir, artifacts_dir=tmp_path / "artifacts", apply=True)
    text = (cards_dir / "CVE-2019-5418.md").read_text(encoding="utf-8")
    assert "title: a " not in text
    assert "File Content Disclosure" in text
    db.close()


def test_is_generic_title():
    assert is_generic_title("windows_10 CVE-2016-0095")
    assert is_generic_title("CVE-2016-0095")
    assert not is_generic_title("Log4j2 JNDI 注入远程代码执行")


# ---------- 概念表 ----------

def test_concepts_have_no_wrong_generic_mappings():
    pairs = {(str(t).lower(), tag) for t, tag, _lang in BUILTIN_CONCEPTS}
    wrong = [
        ("邮件", "command-injection"),
        ("发信", "command-injection"),
        ("sendmail", "command-injection"),
        ("phpmailer", "command-injection"),
        ("换行", "path-traversal"),
        ("越界", "rce"),
        ("写文件", "rce"),
        ("解析", "upload"),
        ("绑定", "deserialization"),
        ("覆盖", "deserialization"),
    ]
    for pair in wrong:
        assert pair not in pairs


def test_expand_concepts_ignores_generic_words(conn):
    assert "command-injection" not in expand_concepts(conn, "邮件服务器版本")
    assert "path-traversal" not in expand_concepts(conn, "响应里的换行符")
    assert "upload" not in expand_concepts(conn, "解析文章内容")
    assert "rce" not in expand_concepts(conn, "数组越界读取")
    assert "lfi" in expand_concepts(conn, "本地文件包含")
    assert "deserialization" in expand_concepts(conn, "数据绑定")


# ---------- GitHub 元数据 artifact ----------

def test_metadata_artifact_sets_poc_path(tmp_path, monkeypatch):
    kb = tmp_path / "kb"
    raw = kb / "raw" / "github-poc" / "2026-11"
    raw.mkdir(parents=True)
    (raw / "CVE-2016-0095.json").write_text(
        json.dumps([{"full_name": "demo/poc", "language": "python",
                     "stargazers_count": 3, "description": "demo"}]), encoding="utf-8")
    monkeypatch.setenv("VULN_ATLAS_KB", str(kb))
    from vuln_atlas.ingest import artifacts as art

    card = _card("CVE-2016-0095", source=["github-poc"], confidence="unverified")
    out = art.apply(card)
    assert out.poc_path == "artifacts/CVE-2016-0095/github-poc-index.txt"
    assert out.poc_type == "github-poc"
    assert out.confidence == "unverified"
    assert (kb / "artifacts" / "CVE-2016-0095" / "github-poc-index.txt").is_file()


def test_unverified_metadata_artifact_gets_no_poc_bonus(tmp_path):
    c = dbm.connect(tmp_path / "index.db")
    dbm.init_db(c)
    common = dict(product="demo", tags=["lfi"], steps="1. curl http://TARGET/x")
    dbm.upsert_card(c, _card("CVE-2999-0001", **common))
    dbm.upsert_card(c, _card("CVE-2999-0002", poc_path="artifacts/CVE-2999-0002/github-poc-index.txt",
                             poc_type="github-poc", **common))
    c.commit()
    res = search(c, build_query(tags=["lfi"]), top_k=5)
    scores = {r["id"]: r["score"] for r in res["results"]}
    assert scores["CVE-2999-0001"] == scores["CVE-2999-0002"]
    c.close()


# ---------- repair / check ----------

def test_repair_retitle_link_export(tmp_path):
    from vuln_atlas.maintenance import repair

    db = dbm.connect(tmp_path / "index.db")
    dbm.init_db(db)
    card = _card(
        "CVE-2016-0095",
        title="windows_10 CVE-2016-0095",
        product="windows_10",
        confidence="unverified",
        source=["github-poc"],
        ident="The kernel-mode driver in Microsoft Windows Vista SP2 allows local users to gain privileges.",
    )
    dbm.upsert_card(db, card)
    db.commit()

    cards_dir = tmp_path / "cards"
    art_dir = tmp_path / "artifacts" / "CVE-2016-0095"
    art_dir.mkdir(parents=True)
    (art_dir / "github-poc-index.txt").write_text("- demo/poc | language=python\n", encoding="utf-8")

    report = repair(db, cards_dir=cards_dir, artifacts_dir=tmp_path / "artifacts", apply=True)
    assert report["exported"] == 1
    md = cards_dir / "CVE-2016-0095.md"
    assert md.is_file()
    assert "CVE-2016-0095" in md.read_text(encoding="utf-8")

    row = dbm.get_card(db, "CVE-2016-0095")
    assert not is_generic_title(row.title)
    assert row.poc_path == "artifacts/CVE-2016-0095/github-poc-index.txt"
    assert row.poc_type == "github-poc"
    db.close()


def test_repair_refreshes_stale_md(tmp_path):
    """DB 变了但同名 md 还在时，repair --sync-md 要把旧内容改写成当前卡。"""
    from vuln_atlas.maintenance import repair

    db = dbm.connect(tmp_path / "index.db")
    dbm.init_db(db)
    card = _card("CVE-2020-9484", title="tomcat CVE-2020-9484", product="tomcat",
                 ident="In Apache Tomcat 9.0, a deserialization flaw exists.")
    dbm.upsert_card(db, card)
    db.commit()

    cards_dir = tmp_path / "cards"
    cards_dir.mkdir()
    (cards_dir / "CVE-2020-9484.md").write_text("stale content\n", encoding="utf-8")

    report = repair(db, cards_dir=cards_dir, artifacts_dir=tmp_path / "artifacts",
                    apply=True, sync_md=True)
    text = (cards_dir / "CVE-2020-9484.md").read_text(encoding="utf-8")
    assert "stale content" not in text
    assert "deserialization flaw" in text
    assert report["refreshed"] == 1
    db.close()


def test_repair_strips_article_from_already_derived_title(tmp_path):
    """上一轮 repair 生成的 "a ..." 标题不是 generic 形态，也要被冠词修复覆盖到。"""
    from vuln_atlas.maintenance import repair

    der = "a File Content Disclosure vulnerability in Action View"
    db = dbm.connect(tmp_path / "index.db")
    dbm.init_db(db)
    dbm.upsert_card(db, _card("CVE-2019-5418", title=der, product="rails", ident=der))
    # 手写标题不能被误改
    dbm.upsert_card(db, _card("CVE-2999-0001", title="A Tour of Go", product="go",
                              ident="a File Content Disclosure vulnerability"))
    db.commit()
    repair(db, cards_dir=tmp_path / "cards", artifacts_dir=tmp_path / "artifacts", apply=True)
    assert dbm.get_card(db, "CVE-2019-5418").title.startswith("File Content")
    assert dbm.get_card(db, "CVE-2999-0001").title == "A Tour of Go"
    db.close()


def test_derive_title_unescapes_yaml_backslashes():
    """frontmatter 里的 `track-it\\!` 是 YAML 转义残留，描述首句用正常写法就直接采用。"""
    t = derive_title(
        r"track-it\! CVE-2016-6599",
        "BMC Track-It! 11.4 before Hotfix 3 exposes an unauthenticated .NET endpoint.",
        product="track-it",
    )
    assert t.startswith("BMC Track-It!")


def test_derive_title_keeps_abbreviation_sentence():
    """`U.S. Air Force` 的缩写点不是句尾，不能被切成 'U.'。"""
    t = derive_title(
        "nitf_extract_utility CVE-2020-13995",
        "U.S. Air Force Sensor Data Management System extract75 has a buffer overflow "
        "that leads to code execution.",
        product="nitf_extract_utility",
    )
    assert t.startswith("U.S. Air Force")


def test_check_reports_cards_db_mismatch(tmp_path):
    from vuln_atlas.maintenance import check

    db = dbm.connect(tmp_path / "index.db")
    dbm.init_db(db)
    dbm.upsert_card(db, _card("CVE-2999-0001"))
    dbm.upsert_card(db, _card("CVE-2999-0002"))
    db.commit()
    cards_dir = tmp_path / "cards"
    cards_dir.mkdir()
    (cards_dir / "CVE-2999-0001.md").write_text(
        render_card(dbm.get_card(db, "CVE-2999-0001")), encoding="utf-8")
    report = check(db, cards_dir=cards_dir)
    assert report["db_cards"] == 2 and report["md_cards"] == 1
    assert report["missing_md"] == ["CVE-2999-0002"]
    assert report["consistent"] is False
    db.close()


def test_check_ignores_non_cve_md(tmp_path):
    from vuln_atlas.maintenance import check

    db = dbm.connect(tmp_path / "index.db")
    dbm.init_db(db)
    dbm.upsert_card(db, _card("CVE-2999-0001", title="real title"))
    db.commit()
    cards_dir = tmp_path / "cards"
    cards_dir.mkdir()
    (cards_dir / "CVE-2999-0001.md").write_text(
        render_card(dbm.get_card(db, "CVE-2999-0001")), encoding="utf-8")
    (cards_dir / ".gitkeep").write_text("", encoding="utf-8")
    report = check(db, cards_dir=cards_dir)
    assert report["consistent"] is True
    db.close()


# ---------- 仓库文件 ----------

def test_repo_has_license_and_mcp_example():
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "MIT License" in license_text
    example = json.loads((ROOT / "mcp.example.json").read_text(encoding="utf-8"))
    server = example["mcpServers"]["vuln-atlas"]
    assert "VULN_ATLAS_DB" in server["env"]
    assert "/home/kali" not in json.dumps(example)
