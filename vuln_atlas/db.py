from __future__ import annotations

import json
import sqlite3
from pathlib import Path

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
    steps TEXT,
    marker TEXT,
    confidence TEXT NOT NULL DEFAULT 'candidate',
    last_verified TEXT,
    source TEXT NOT NULL DEFAULT '[]',
    body TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS cards_cve ON cards(cve);
CREATE INDEX IF NOT EXISTS cards_product ON cards(product);
CREATE VIRTUAL TABLE IF NOT EXISTS cards_fts USING fts5(
    id, cve, title, aliases, product, tags, fingerprint, body,
    content='cards',
    content_rowid='rowid',
    tokenize='trigram'
);
CREATE TRIGGER IF NOT EXISTS cards_ai AFTER INSERT ON cards BEGIN
    INSERT INTO cards_fts(rowid, id, cve, title, aliases, product, tags, fingerprint, body)
    VALUES (new.rowid, new.id, new.cve, new.title, new.aliases, new.product, new.tags, new.fingerprint, new.body);
END;
CREATE TRIGGER IF NOT EXISTS cards_ad AFTER DELETE ON cards BEGIN
    INSERT INTO cards_fts(cards_fts, rowid, id, cve, title, aliases, product, tags, fingerprint, body)
    VALUES ('delete', old.rowid, old.id, old.cve, old.title, old.aliases, old.product, old.tags, old.fingerprint, old.body);
END;
CREATE TRIGGER IF NOT EXISTS cards_au AFTER UPDATE ON cards BEGIN
    INSERT INTO cards_fts(cards_fts, rowid, id, cve, title, aliases, product, tags, fingerprint, body)
    VALUES ('delete', old.rowid, old.id, old.cve, old.title, old.aliases, old.product, old.tags, old.fingerprint, old.body);
    INSERT INTO cards_fts(rowid, id, cve, title, aliases, product, tags, fingerprint, body)
    VALUES (new.rowid, new.id, new.cve, new.title, new.aliases, new.product, new.tags, new.fingerprint, new.body);
END;
"""


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(path: str | Path) -> sqlite3.Connection:
    conn = connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def upsert_card(conn: sqlite3.Connection, card: dict) -> None:
    fields = [
        "id", "cve", "title", "aliases", "vendor", "product", "versions",
        "fingerprint", "tags", "attack_surface", "poc_type", "poc_path",
        "steps", "marker", "confidence", "last_verified", "source", "body",
    ]
    values = []
    for key in fields:
        value = card.get(key)
        if key in {"aliases", "versions", "fingerprint", "tags", "attack_surface", "source"}:
            value = json.dumps(value or [], ensure_ascii=False)
        values.append(value if value is not None else "" if key not in {"cve", "poc_type", "poc_path", "steps", "marker", "last_verified"} else None)
    placeholders = ",".join("?" for _ in fields)
    conn.execute(
        f"INSERT INTO cards ({','.join(fields)}) VALUES ({placeholders}) "
        "ON CONFLICT(id) DO UPDATE SET "
        + ",".join(f"{field}=excluded.{field}" for field in fields if field != "id"),
        values,
    )
