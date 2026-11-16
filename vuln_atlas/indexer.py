"""cards/*.md -> index.db 的编排：校验、去重、入库（§8.1 阶段 5/6）。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import db as dbm
from . import paths
from .card import Card, card_from_text, render_card, validate_card, scan_secrets, LIMIT_CARD_BYTES
from .ingest.common import Manifest, now_iso


def load_cards(cards_dir: Optional[Path] = None) -> List[Tuple[Path, Card]]:
    d = cards_dir or paths.cards_dir()
    out = []
    for p in sorted(d.glob("*.md")):
        try:
            card = card_from_text(p.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            print(f"[skip] 解析失败 {p.name}: {e}")
            continue
        if not card.id:
            print(f"[skip] 缺 id: {p.name}")
            continue
        if not card.title:
            print(f"[skip] 缺 title: {p.name}")
            continue
        out.append((p, card))
    return out


def check_card(card: Card, artifacts_dir: Optional[Path] = None) -> List[str]:
    """校验 + 密钥扫描；返回阻断性问题。"""
    art = artifacts_dir or paths.artifacts_dir()
    issues = validate_card(card, artifacts_root=paths.kb_root())
    blocking = []
    for i in issues:
        if i == "poc_missing":
            # 降级而非拒绝
            card.confidence = "candidate"
            continue
        blocking.append(i)
    text = render_card(card)
    leaks = scan_secrets(text)
    if leaks:
        blocking.append("密钥/flag 命中: " + ",".join(leaks))
    return blocking


def build_index(db_file: Optional[Path] = None, cards_dir: Optional[Path] = None,
                write_manifest: bool = True) -> Dict[str, object]:
    from .rank import BUILTIN_CONCEPTS

    db_file = db_file or paths.db_path()
    conn = dbm.connect(db_file)
    dbm.init_db(conn)
    loaded = load_cards(cards_dir)
    stats = {"total": len(loaded), "indexed": 0, "rejected": 0, "downgraded": 0, "reasons": {}}
    seen: Dict[str, str] = {}
    cards: List[Card] = []

    for p, card in loaded:
        before = card.confidence
        blocking = check_card(card)
        if blocking:
            stats["rejected"] += 1
            for b in blocking:
                stats["reasons"][b] = stats["reasons"].get(b, 0) + 1
            print(f"[reject] {p.name}: {'; '.join(blocking)}")
            continue
        if card.confidence != before:
            stats["downgraded"] += 1
            print(f"[downgrade] {p.name}: {before} -> {card.confidence} (poc_path 缺失)")
        key = card.id.upper()
        if key in seen:
            stats["rejected"] += 1
            stats["reasons"]["重复 id"] = stats["reasons"].get("重复 id", 0) + 1
            print(f"[reject] {p.name}: 重复 id {card.id}（已见 {seen[key]}）")
            continue
        seen[key] = p.name
        cards.append(card)
        stats["indexed"] += 1

    dbm.upsert_many(conn, cards)
    dbm.rebuild_term_df(conn)
    dbm.load_concepts(conn, [
        {"term": t, "canonical_tag": tag, "lang": lang, "source": "builtin", "confidence": 0.6}
        for t, tag, lang in BUILTIN_CONCEPTS
    ])

    if write_manifest:
        m = Manifest(paths.manifest_path())
        m.data["index"] = {
            "built_at": now_iso(),
            "db": str(db_file),
            "cards_loaded": stats["total"],
            "cards_indexed": stats["indexed"],
            "cards_rejected": stats["rejected"],
            "downgraded": stats["downgraded"],
            "reasons": stats["reasons"],
        }
        m.save()

    conn.close()
    return stats
