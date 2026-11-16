"""SQLite FTS5 索引层：建表 / 写入 / 读取（§4.3）。"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .card import Card

SCHEMA = """
CREATE TABLE IF NOT EXISTS cards (
  id TEXT PRIMARY KEY,
  cve TEXT,
  title TEXT NOT NULL,
  aliases TEXT NOT NULL DEFAULT '[]',
  vendor TEXT,
  product TEXT,
  versions TEXT NOT NULL DEFAULT '[]',
  fingerprint TEXT NOT NULL DEFAULT '[]',
  tags TEXT NOT NULL DEFAULT '[]',
  attack_surface TEXT NOT NULL DEFAULT '[]',
  poc_type TEXT,
  poc_path TEXT,
  poc_code TEXT,
  steps TEXT,
  marker TEXT,
  confidence TEXT NOT NULL,
  last_verified TEXT,
  source TEXT NOT NULL DEFAULT '[]',
  license TEXT,
  body TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- §14：body 只索引摘要，全文留在 cards 表。
-- trigram 索引对每个字符位置建 token，全文 9.6MB 会膨胀到 ~190MB（已实测），
-- 只索引前 300 字节摘要可把索引压到 ~30MB，且不损失识别能力（关键信息在开头）。
CREATE VIRTUAL TABLE IF NOT EXISTS cards_fts USING fts5(
  id, cve, title, aliases, product, tags, fingerprint, body,
  content='cards_fts_src',
  content_rowid='rowid',
  tokenize='trigram'
);

-- FTS 的"内容源"表：只保存摘要，避免 trigram 对全文膨胀。
-- 由 upsert_card() 显式维护，并用触发器保持与 cards 一致。
CREATE TABLE IF NOT EXISTS cards_fts_src (
  rowid INTEGER PRIMARY KEY,
  id TEXT, cve TEXT, title TEXT, aliases TEXT, product TEXT,
  tags TEXT, fingerprint TEXT, body TEXT
);

CREATE TABLE IF NOT EXISTS card_terms (
  card_id TEXT NOT NULL,
  kind TEXT NOT NULL,          -- tag | surface
  term TEXT NOT NULL,
  PRIMARY KEY (card_id, kind, term)
);
CREATE INDEX IF NOT EXISTS idx_card_terms_term ON card_terms(term);

-- 中文 bigram 索引：trigram 需要 >=3 字符才能命中，而中文关键词常是 2 字
-- （配置/绑定/邮件/解析）。这里把 CJK 文本切成 bigram 存进 unicode61 索引，
-- 查询 2 字词时直接命中对应 bigram，3+ 字词则要求其全部 bigram 共现（AND）。
CREATE TABLE IF NOT EXISTS cards_cjk_src (
  rowid INTEGER PRIMARY KEY,
  bigrams TEXT
);

CREATE VIRTUAL TABLE IF NOT EXISTS cards_cjk USING fts5(
  bigrams,
  content='cards_cjk_src',
  content_rowid='rowid',
  tokenize='unicode61'
);

CREATE TRIGGER IF NOT EXISTS cjk_src_ai AFTER INSERT ON cards_cjk_src BEGIN
  INSERT INTO cards_cjk(rowid, bigrams) VALUES (new.rowid, new.bigrams);
END;

CREATE TRIGGER IF NOT EXISTS cjk_src_ad AFTER DELETE ON cards_cjk_src BEGIN
  INSERT INTO cards_cjk(cards_cjk, rowid, bigrams) VALUES ('delete', old.rowid, old.bigrams);
END;

CREATE TRIGGER IF NOT EXISTS cjk_src_au AFTER UPDATE ON cards_cjk_src BEGIN
  INSERT INTO cards_cjk(cards_cjk, rowid, bigrams) VALUES ('delete', old.rowid, old.bigrams);
  INSERT INTO cards_cjk(rowid, bigrams) VALUES (new.rowid, new.bigrams);
END;

-- FTS5 词表：term -> 文档数，用于快速查自由文本词的 df（避免逐词 count MATCH）
CREATE VIRTUAL TABLE IF NOT EXISTS fts_vocab USING fts5vocab(cards_fts, 'row');

CREATE TABLE IF NOT EXISTS term_df (
  term TEXT PRIMARY KEY,
  df INTEGER NOT NULL,
  built_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS concepts (
  term TEXT NOT NULL,
  canonical_tag TEXT NOT NULL,
  lang TEXT NOT NULL,
  source TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 0.5,
  PRIMARY KEY (term, canonical_tag)
);

-- 外部内容表模式：FTS 通过 cards_fts_src 读写，由下面的触发器保持同步。
CREATE TRIGGER IF NOT EXISTS fts_src_ai AFTER INSERT ON cards_fts_src BEGIN
  INSERT INTO cards_fts(rowid, id, cve, title, aliases, product, tags, fingerprint, body)
  VALUES (new.rowid, new.id, new.cve, new.title, new.aliases, new.product, new.tags,
          new.fingerprint, new.body);
END;

CREATE TRIGGER IF NOT EXISTS fts_src_ad AFTER DELETE ON cards_fts_src BEGIN
  INSERT INTO cards_fts(cards_fts, rowid, id, cve, title, aliases, product, tags, fingerprint, body)
  VALUES ('delete', old.rowid, old.id, old.cve, old.title, old.aliases, old.product,
          old.tags, old.fingerprint, old.body);
END;

CREATE TRIGGER IF NOT EXISTS fts_src_au AFTER UPDATE ON cards_fts_src BEGIN
  INSERT INTO cards_fts(cards_fts, rowid, id, cve, title, aliases, product, tags, fingerprint, body)
  VALUES ('delete', old.rowid, old.id, old.cve, old.title, old.aliases, old.product,
          old.tags, old.fingerprint, old.body);
  INSERT INTO cards_fts(rowid, id, cve, title, aliases, product, tags, fingerprint, body)
  VALUES (new.rowid, new.id, new.cve, new.title, new.aliases, new.product, new.tags,
          new.fingerprint, new.body);
END;

CREATE INDEX IF NOT EXISTS idx_cards_cve ON cards(cve);
CREATE INDEX IF NOT EXISTS idx_cards_product ON cards(product);
CREATE INDEX IF NOT EXISTS idx_cards_confidence ON cards(confidence);
"""

FTS_COLUMNS = ["id", "cve", "title", "aliases", "product", "tags", "fingerprint", "body"]


def connect(db_file: Path | str, readonly: bool = False) -> sqlite3.Connection:
    p = Path(db_file)
    if readonly and not p.exists():
        raise FileNotFoundError(f"index.db 不存在: {p}")
    if readonly:
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(p)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if not readonly:
        conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def _json(v: Any) -> str:
    return json.dumps(v or [], ensure_ascii=False)


_CJK_RUN = re.compile(r"[\u4e00-\u9fff]{2,}")


def cjk_bigrams(text: str) -> str:
    """把 CJK 连续串切成空格分隔的 bigram（'配置绑定' -> '配置 置绑 绑定'）。"""
    out = []
    for run in _CJK_RUN.findall(text or ""):
        for i in range(len(run) - 1):
            out.append(run[i:i + 2])
    return " ".join(dict.fromkeys(out))


def cjk_remove(conn: sqlite3.Connection, card_id: str) -> None:
    """删 cards_cjk_src 中的旧 bigram（触发器同步删除 FTS 索引项）。"""
    conn.execute("DELETE FROM cards_cjk_src WHERE rowid IN "
                 "(SELECT rowid FROM cards WHERE id = ?)", (card_id,))


def fts_remove(conn: sqlite3.Connection, card_id: str) -> None:
    """删除 cards_fts_src 中的旧摘要（触发器会同步删除 FTS 索引项）。"""
    conn.execute("DELETE FROM cards_fts_src WHERE id = ?", (card_id,))


def upsert_card(conn: sqlite3.Connection, card: Card) -> None:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    secs = card.sections()
    fts_remove(conn, card.id)
    cjk_remove(conn, card.id)
    conn.execute("DELETE FROM card_terms WHERE card_id = ?", (card.id,))
    for term in set(card.tags):
        conn.execute("INSERT OR IGNORE INTO card_terms(card_id,kind,term) VALUES (?,?,?)",
                     (card.id, "tag", str(term).lower()))
    for term in set(card.attack_surface):
        conn.execute("INSERT OR IGNORE INTO card_terms(card_id,kind,term) VALUES (?,?,?)",
                     (card.id, "surface", str(term).lower()))

    conn.execute(
        """
        INSERT INTO cards (
          id, cve, title, aliases, vendor, product, versions, fingerprint, tags,
          attack_surface, poc_type, poc_path, poc_code, steps, marker, confidence,
          last_verified, source, license, body, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
          cve=excluded.cve, title=excluded.title, aliases=excluded.aliases,
          vendor=excluded.vendor, product=excluded.product, versions=excluded.versions,
          fingerprint=excluded.fingerprint, tags=excluded.tags,
          attack_surface=excluded.attack_surface, poc_type=excluded.poc_type,
          poc_path=excluded.poc_path, poc_code=excluded.poc_code, steps=excluded.steps,
          marker=excluded.marker, confidence=excluded.confidence,
          last_verified=excluded.last_verified, source=excluded.source,
          license=excluded.license, body=excluded.body, updated_at=excluded.updated_at
        """,
        (
            card.id, card.cve, card.title, _json(card.aliases), card.vendor, card.product,
            _json(card.versions), _json(card.fingerprint), _json(card.tags),
            _json(card.attack_surface), card.poc_type, card.poc_path, card.poc_code,
            secs.get("最小步骤"), secs.get("预期 marker"), card.confidence,
            card.last_verified, _json(card.source), card.license, card.body, now,
        ),
    )
    row = conn.execute("SELECT rowid FROM cards WHERE id = ?", (card.id,)).fetchone()
    if row is not None:
        conn.execute(
            "INSERT OR REPLACE INTO cards_fts_src"
            "(rowid, id, cve, title, aliases, product, tags, fingerprint, body) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                row["rowid"], card.id, card.cve, card.title, _json(card.aliases),
                card.product, _json(card.tags), _json(card.fingerprint),
                card.body[:600],
            ),
        )
        bg = cjk_bigrams(card.title + " " + " ".join(card.tags) + " " + card.body[:600])
        conn.execute("DELETE FROM cards_cjk_src WHERE rowid = ?", (row["rowid"],))
        if bg:
            conn.execute("INSERT INTO cards_cjk_src(rowid, bigrams) VALUES (?, ?)",
                         (row["rowid"], bg))


def upsert_many(conn: sqlite3.Connection, cards: Iterable[Card]) -> int:
    n = 0
    for c in cards:
        upsert_card(conn, c)
        n += 1
    conn.commit()
    return n


def row_to_card(row: sqlite3.Row) -> Card:
    def j(k):
        try:
            return json.loads(row[k]) if row[k] else []
        except (TypeError, json.JSONDecodeError):
            return []
    keys = row.keys()
    return Card(
        id=row["id"],
        cve=row["cve"],
        title=row["title"],
        aliases=j("aliases"),
        vendor=row["vendor"],
        product=row["product"],
        versions=j("versions"),
        fingerprint=j("fingerprint"),
        tags=j("tags"),
        attack_surface=j("attack_surface"),
        poc_type=row["poc_type"],
        poc_path=row["poc_path"],
        poc_code=row["poc_code"],
        confidence=row["confidence"],
        last_verified=row["last_verified"],
        source=j("source"),
        license=row["license"] if "license" in keys else None,
        body=row["body"],
    )


def get_card(conn: sqlite3.Connection, cid: str) -> Optional[Card]:
    row = conn.execute("SELECT * FROM cards WHERE id = ?", (cid,)).fetchone()
    if row is None:
        r = conn.execute("SELECT * FROM cards WHERE upper(cve) = upper(?)", (cid,)).fetchone()
        row = r
    return row_to_card(row) if row else None


def get_by_cve(conn: sqlite3.Connection, cve: str) -> Optional[Card]:
    row = conn.execute("SELECT * FROM cards WHERE upper(cve) = upper(?)", (cve,)).fetchone()
    return row_to_card(row) if row else None


def all_cards(conn: sqlite3.Connection) -> List[Card]:
    return [row_to_card(r) for r in conn.execute("SELECT * FROM cards")]


def stats(conn: sqlite3.Connection) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    out["cards"] = conn.execute("SELECT count(*) c FROM cards").fetchone()["c"]
    for col in ("confidence", "poc_type"):
        out[col] = {
            r[col] or "-": r["c"]
            for r in conn.execute(f"SELECT {col}, count(*) c FROM cards GROUP BY {col}")
        }
    out["with_cve"] = conn.execute("SELECT count(*) c FROM cards WHERE cve IS NOT NULL").fetchone()["c"]
    out["with_poc"] = conn.execute(
        "SELECT count(*) c FROM cards WHERE poc_path IS NOT NULL OR poc_code IS NOT NULL"
    ).fetchone()["c"]
    out["concepts"] = conn.execute("SELECT count(*) c FROM concepts").fetchone()["c"]
    try:
        out["term_df"] = conn.execute("SELECT count(*) c FROM term_df").fetchone()["c"]
    except sqlite3.Error:
        out["term_df"] = 0
    return out


def rebuild_term_df(conn: sqlite3.Connection) -> int:
    """统计每个 tag/surface 词的文档频率，供 idf 使用（构建期一次，查询期查表）。"""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute("DELETE FROM term_df")
    conn.execute(
        "INSERT INTO term_df(term, df, built_at) "
        "SELECT term, count(*) , ? FROM card_terms GROUP BY term", (now,)
    )
    n = conn.execute("SELECT count(*) c FROM term_df").fetchone()["c"]
    conn.commit()
    return n


def get_term_df(conn: sqlite3.Connection, terms: List[str]) -> Dict[str, int]:
    """优先查 term_df（tag/surface），缺失的从 fts_vocab 补（自由文本词）。"""
    if not terms:
        return {}
    out: Dict[str, int] = {}
    ph = ",".join("?" * len(terms))
    try:
        for r in conn.execute(
            f"SELECT term, df FROM term_df WHERE term IN ({ph})", list(terms)
        ):
            out[r["term"]] = r["df"]
    except sqlite3.Error:
        pass
    # 自由文本词：fts_vocab 的 doc 是出现次数而非文档数，不适用；
    # 直接 count(*)，单词 count 通常在 1–20ms，且只在少量词上发生。
    missing = [t for t in terms if t not in out]
    for t in missing:
        try:
            n = conn.execute(
                "SELECT count(*) c FROM cards_fts WHERE cards_fts MATCH ?", ('"' + t.replace('"', '""') + '"',)
            ).fetchone()["c"]
            out[t] = n
        except sqlite3.Error:
            out[t] = 0
    return out


def load_concepts(conn: sqlite3.Connection, rows: Iterable[Dict[str, Any]],
                  replace_builtin: bool = False) -> int:
    """写入概念映射。

    replace_builtin=True 时先删掉旧的 builtin 行，保证 BUILDIN_CONCEPTS 的
    修正能真正生效（否则删掉的错误映射会作为陈旧行一直留在库里）。
    """
    n = 0
    if replace_builtin:
        conn.execute("DELETE FROM concepts WHERE source = 'builtin'")
    for r in rows:
        conn.execute(
            "INSERT INTO concepts(term, canonical_tag, lang, source, confidence) VALUES (?,?,?,?,?) "
            "ON CONFLICT(term, canonical_tag) DO UPDATE SET lang=excluded.lang, "
            "source=excluded.source, confidence=excluded.confidence",
            (
                str(r["term"]).strip().lower(),
                str(r["canonical_tag"]).strip().lower(),
                str(r.get("lang", "zh")),
                str(r.get("source", "curated")),
                float(r.get("confidence", 0.6)),
            ),
        )
        n += 1
    conn.commit()
    return n


def concepts_for(conn: sqlite3.Connection, term: str) -> List[sqlite3.Row]:
    return list(conn.execute("SELECT * FROM concepts WHERE term = ?", (term.strip().lower(),)))
