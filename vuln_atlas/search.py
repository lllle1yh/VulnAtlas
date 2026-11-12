from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
STOP_PHRASES = (
    "怎么打", "怎么利用", "如何利用", "如何打", "怎么复现", "如何复现",
    "有没有", "是什么", "什么", "漏洞", "利用", "复现", "请问", "怎么", "如何",
)
SYNONYMS = {
    "本地文件包含": "lfi",
    "文件包含": "lfi",
    "路径穿越": "path traversal",
    "目录穿越": "path traversal",
    "远程代码执行": "rce",
    "命令执行": "command execution",
    "反序列化": "deserialization",
    "sql注入": "sql injection",
    "未授权": "auth bypass",
}


def _json(value: Any) -> list:
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(value or "[]")
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def _row(row: sqlite3.Row, score: float = 0.0, why: str = "") -> dict:
    return {
        "id": row["id"],
        "cve": row["cve"],
        "title": row["title"],
        "aliases": _json(row["aliases"]),
        "vendor": row["vendor"],
        "product": row["product"],
        "versions": _json(row["versions"]),
        "fingerprint": _json(row["fingerprint"]),
        "tags": _json(row["tags"]),
        "attack_surface": _json(row["attack_surface"]),
        "poc_type": row["poc_type"],
        "poc_path": row["poc_path"],
        "steps": row["steps"],
        "marker": row["marker"],
        "confidence": row["confidence"],
        "last_verified": row["last_verified"],
        "source": _json(row["source"]),
        "body": row["body"],
        "score": round(float(score), 3),
        "why": why,
    }


def get_card(conn: sqlite3.Connection, card_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM cards WHERE id = ?", (card_id,)).fetchone()
    return _row(row) if row else None


def search(
    conn: sqlite3.Connection,
    *,
    query: str = "",
    product: str | None = None,
    version: str | None = None,
    cve: str | None = None,
    tags: list[str] | None = None,
    top_k: int = 5,
) -> list[dict]:
    limit = max(1, min(int(top_k), 20))
    cve = (cve or "").upper().strip() or None
    if not cve and query:
        match = CVE_RE.search(query)
        cve = match.group(0).upper() if match else None
    if cve:
        rows = conn.execute("SELECT * FROM cards WHERE upper(cve) = ? LIMIT ?", (cve, limit)).fetchall()
        if rows:
            return [_row(row, 100.0, "cve_exact") for row in rows]
    structured = []
    clauses = []
    params: list = []
    if product:
        clauses.append("(lower(product) = lower(?) OR lower(aliases) LIKE ?)")
        params.extend([product, f"%{product.lower()}%"])
    if tags:
        for tag in tags:
            clauses.append("lower(tags) LIKE ?")
            params.append(f"%{tag.lower()}%")
    if clauses:
        structured = conn.execute(
            "SELECT * FROM cards WHERE " + " AND ".join(clauses) + " LIMIT 50",
            params,
        ).fetchall()
    if version:
        structured = [row for row in structured if _version_match(row["versions"], version)]
    if structured:
        rows = structured[:limit]
        return [_row(row, 50.0, "product_version" if version or product else "tags") for row in rows]
    if not query:
        return []
    fts_query = _fts_query(query, _vocabulary(conn))
    try:
        rows = conn.execute(
            "SELECT cards.*, bm25(cards_fts, 0, 10, 8, 5, 6, 4, 3, 1) AS rank "
            "FROM cards_fts JOIN cards ON cards.rowid = cards_fts.rowid "
            "WHERE cards_fts MATCH ? ORDER BY rank LIMIT ?",
            (fts_query, 50),
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    if version:
        rows = [row for row in rows if _version_match(row["versions"], version)]
    return [_row(row, -float(row["rank"]), "bm25") for row in rows[:limit]]


def normalize_query(query: str, vocab: set[str] | None = None) -> list[str]:
    text = str(query or "").lower()
    for phrase in STOP_PHRASES:
        text = text.replace(phrase, " ")
    for phrase, replacement in SYNONYMS.items():
        if phrase in text:
            text = text.replace(phrase, f" {replacement} ")
    vocab = vocab or set()
    tokens: list[str] = []
    for raw in re.findall(r"[A-Za-z0-9_.:/-]+|[一-鿿]+", text):
        token = raw.strip()
        if not token:
            continue
        tokens.extend(_segment_token(token, vocab))
    seen = []
    for token in tokens:
        if token not in seen:
            seen.append(token)
    return seen[:16]


def _segment_token(token: str, vocab: set[str]) -> list[str]:
    if not token or not re.fullmatch(r"[a-z0-9_-]+", token) or token in vocab:
        return [token]
    # Dynamic programming segmentation over the card vocabulary. No
    # product-specific aliases live in code; the vocabulary comes from cards.
    best: dict[int, list[str]] = {0: []}
    for end in range(1, len(token) + 1):
        candidates = []
        for start in range(max(0, end - 24), end):
            if start not in best:
                continue
            piece = token[start:end]
            if piece in vocab and len(piece) >= 2:
                candidates.append(best[start] + [piece])
        if candidates:
            best[end] = min(candidates, key=len)
    if len(token) in best and len(best[len(token)]) > 1:
        return best[len(token)]
    return [token]


def _vocabulary(conn: sqlite3.Connection) -> set[str]:
    vocab: set[str] = set()
    for row in conn.execute("SELECT title, aliases, product, tags FROM cards"):
        for value in (row["title"], row["product"]):
            for word in re.findall(r"[A-Za-z0-9]+", str(value or "").lower()):
                if len(word) >= 2:
                    vocab.add(word)
        for key in ("aliases", "tags"):
            for item in _json(row[key]):
                for word in re.findall(r"[A-Za-z0-9]+", str(item).lower()):
                    if len(word) >= 2:
                        vocab.add(word)
    return vocab


def _fts_query(query: str, vocab: set[str] | None = None) -> str:
    tokens = normalize_query(query, vocab)
    if not tokens:
        return '""'
    return " OR ".join(f'"{token}"' for token in tokens[:12])
def _fts_query(query: str) -> str:
    tokens = normalize_query(query)
    if not tokens:
        return '""'
    return " OR ".join(f'"{token}"' for token in tokens[:12])


def _version_match(versions_json: str, wanted: str) -> bool:
    versions = _json(versions_json)
    if not versions:
        return False
    wanted_tuple = _version_tuple(wanted)
    for expr in versions:
        expr = str(expr).strip()
        if not expr:
            continue
        if expr in {"*", "any"}:
            return True
        if expr.startswith("<=") and wanted_tuple <= _version_tuple(expr[2:]):
            return True
        if expr.startswith(">=") and wanted_tuple >= _version_tuple(expr[2:]):
            return True
        if expr.startswith("<") and wanted_tuple < _version_tuple(expr[1:]):
            return True
        if expr.startswith(">") and wanted_tuple > _version_tuple(expr[1:]):
            return True
        if expr.startswith("=") and wanted_tuple == _version_tuple(expr[1:]):
            return True
        if _version_tuple(expr) == wanted_tuple:
            return True
    return False


def _version_tuple(value: str) -> tuple:
    parts = re.findall(r"\d+|[A-Za-z]+", str(value))
    return tuple(int(part) if part.isdigit() else part for part in parts)
