"""知识库维护：`check` 报告不一致，`repair` 就地修正。

修的都是"成品层"的问题，不动 ingest 逻辑：
  1. 低信息量标题（`<product> CVE-xxxx-xxxxx`）→ 正文首句
  2. 仅元数据卡已有本地 `github-poc-index.txt`，但 poc_path 为空 → 关联上
  3. DB 有、cards/*.md 没有 → 导出 Markdown
  4. concepts 表里的陈旧/错误 builtin 映射 → 与 BUILTIN_CONCEPTS 对齐
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import db as dbm
from . import paths
from .card import Card, is_generic_title, render_card, title_from_description

META_ARTIFACT = "github-poc-index.txt"
# 描述里常见的引导词。旧版 derive 只剥一次，会残留一个。
_LEAD_WORDS = ("a ", "an ", "the ", "in ", "on ", "this ", "there is ")


def _rel_artifact_path(cve: str, artifacts_dir: Path) -> Optional[str]:
    """若该 CVE 已有本地元数据文件，返回规范化的 kb 相对路径。"""
    if not cve:
        return None
    f = Path(artifacts_dir) / cve / META_ARTIFACT
    if not f.is_file() or f.stat().st_size == 0:
        return None
    # 与 ingest 产出保持同一形态：artifacts/<CVE>/<file>
    return f"artifacts/{cve}/{META_ARTIFACT}"


def title_from_body(card: Card) -> Optional[str]:
    """从正文第一段抽出描述，生成标题；抽不出有信息量的句子时返回 None。

    不看当前标题，所以对"上一轮已经由描述生成、但带冠词"的标题同样生效。
    正文形如 "<product> 版本 1.2；指纹：x。The foo in bar allows ..."
    """
    first = card.section("目标特征 / 版本") or ""
    ident = first.split("。", 1)[-1] if "。" in first else first
    return title_from_description(ident)


def retitle(conn: sqlite3.Connection, limit: int = 10 ** 9) -> List[str]:
    """把泛化标题改成描述首句；返回被改动的 id。"""
    changed: List[str] = []
    rows = conn.execute(
        "SELECT * FROM cards WHERE title IS NOT NULL"
    ).fetchall()
    for row in rows:
        card = dbm.row_to_card(row)
        # 只改两类标题：泛化标题，以及上一轮从描述生成、但多留了一个引导词的标题
        # （如 "There is a X" 只剥了 "There is"，留下 "a X"）。手写标题不动。
        new = title_from_body(card)
        if not new or new == card.title:
            continue
        if not is_generic_title(card.title):
            legacy = {f"{lead}{new}".casefold() for lead in _LEAD_WORDS}
            if card.title.casefold() not in legacy:
                continue
        if is_generic_title(new) or new == card.title:
            continue
        dbm.upsert_card(conn, replace(card, title=new))
        changed.append(card.id)
        if len(changed) >= limit:
            break
    conn.commit()
    return changed


def link_metadata_artifacts(conn: sqlite3.Connection, artifacts_dir: Path) -> List[str]:
    """把已有 github-poc-index.txt 但 poc_path 为空的卡关联上（不加置信度）。"""
    linked: List[str] = []
    rows = conn.execute(
        "SELECT * FROM cards WHERE (poc_path IS NULL OR poc_path = '') AND cve IS NOT NULL"
    ).fetchall()
    for row in rows:
        card = dbm.row_to_card(row)
        rel = _rel_artifact_path(card.cve, artifacts_dir)
        if not rel:
            continue
        card.poc_path = rel
        card.poc_type = card.poc_type or "github-poc"
        secs = card.sections()
        secs["证据指针"] = f"本地证据：{rel}（GitHub PoC 元数据，非源码）"
        card.set_sections(secs)
        dbm.upsert_card(conn, card)
        linked.append(card.id)
    conn.commit()
    return linked


def export_cards(conn: sqlite3.Connection, cards_dir: Path,
                 write: bool = True, sync_md: bool = False) -> Tuple[List[str], List[str]]:
    """把 DB 卡导出到 cards/，返回 (新增, 重写)。

    sync_md=True 时，同名文件内容与 DB 不一致也重写，保证 cards/ 真是 DB 的镜像。
    write=False 只统计不落盘。
    """
    existing = {p.name.lower(): p for p in cards_dir.glob("*.md")} if cards_dir.is_dir() else {}
    if write:
        cards_dir.mkdir(parents=True, exist_ok=True)
    exported: List[str] = []
    refreshed: List[str] = []
    rows = conn.execute("SELECT * FROM cards ORDER BY id").fetchall()
    for row in rows:
        card = dbm.row_to_card(row)
        name = f"{card.cve or card.id}.md"
        old = existing.get(name.lower())
        text = render_card(card)
        if old is not None:
            if not sync_md:
                continue
            try:
                if old.read_text(encoding="utf-8") == text:
                    continue
            except OSError:
                pass
            if write:
                old.write_text(text, encoding="utf-8")
            refreshed.append(card.id)
            continue
        if write:
            (cards_dir / name).write_text(text, encoding="utf-8")
        exported.append(card.id)
    return exported, refreshed


def sync_concepts(conn: sqlite3.Connection) -> int:
    """让 concepts 表的 builtin 行与代码里的 BUILTIN_CONCEPTS 完全一致。"""
    from .rank import BUILTIN_CONCEPTS

    return dbm.load_concepts(conn, [
        {"term": t, "canonical_tag": tag, "lang": lang, "source": "builtin", "confidence": 0.6}
        for t, tag, lang in BUILTIN_CONCEPTS
    ], replace_builtin=True)


def check(conn: sqlite3.Connection, cards_dir: Optional[Path] = None) -> Dict[str, object]:
    """只读体检：DB / cards / artifacts 是否一致。"""
    cards_dir = Path(cards_dir or paths.cards_dir())
    db_ids = [r["id"] for r in conn.execute("SELECT id FROM cards ORDER BY id")]
    md_ids: List[str] = []
    if cards_dir.is_dir():
        # cards/ 是生成目录，*.md 都算卡；非卡文件由 missing_db 报出来，
        # 不做静默过滤（否则畸形 id 的卡会假性"一致"）。
        for p in sorted(cards_dir.glob("*.md")):
            md_ids.append(p.stem)
    db_set, md_set = set(db_ids), set(md_ids)
    generic = sum(
        1 for r in conn.execute("SELECT title FROM cards WHERE title LIKE '%CVE-%'")
        if is_generic_title(r["title"])
    )
    unlinked = conn.execute(
        "SELECT count(*) c FROM cards WHERE (poc_path IS NULL OR poc_path = '') AND cve IS NOT NULL"
    ).fetchone()["c"]
    return {
        "db_cards": len(db_ids),
        "md_cards": len(md_ids),
        "missing_md": sorted(db_set - md_set),
        "missing_db": sorted(md_set - db_set),
        "generic_titles": generic,
        "unlinked_cve": unlinked,
        "consistent": db_set == md_set,
    }


def repair(conn: sqlite3.Connection, cards_dir: Optional[Path] = None,
           artifacts_dir: Optional[Path] = None, apply: bool = False,
           sync_md: bool = False) -> Dict[str, object]:
    """先修复再导出（导出才能反映修好的标题），最后同步概念表。

    apply=False 时只计算不落盘，方便先看规模；sync_md=True 时连已有 md 一起刷新。
    """
    cards_dir = Path(cards_dir or paths.cards_dir())
    artifacts_dir = Path(artifacts_dir or paths.artifacts_dir())

    retitled: List[str] = []
    linked: List[str] = []
    exported: List[str] = []
    refreshed: List[str] = []

    if apply:
        retitled = retitle(conn)
        linked = link_metadata_artifacts(conn, artifacts_dir)
    else:
        for row in conn.execute("SELECT * FROM cards"):
            card = dbm.row_to_card(row)
            if is_generic_title(card.title) and not is_generic_title(title_from_body(card)):
                retitled.append(card.id)
        for row in conn.execute(
            "SELECT id, cve FROM cards WHERE (poc_path IS NULL OR poc_path = '') AND cve IS NOT NULL"
        ):
            if _rel_artifact_path(row["cve"], artifacts_dir):
                linked.append(row["id"])

    exported, refreshed = export_cards(conn, cards_dir, write=apply, sync_md=sync_md)
    concepts = sync_concepts(conn) if apply else 0
    return {
        "refreshed": len(refreshed),
        "retitled": len(retitled),
        "linked": len(linked),
        "exported": len(exported),
        "concepts": concepts,
        "applied": apply,
    }
