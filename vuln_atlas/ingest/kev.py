"""CISA KEV 解析器：cve -> 已知被利用标记（enrich 字段）。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterator

from .common import CardDraft


def parse(path: Path) -> Iterator[Dict[str, object]]:
    """产出 enrich 记录，不单独建卡。"""
    data = json.loads(path.read_text(encoding="utf-8"))
    for v in data.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").upper()
        if not cve:
            continue
        yield {
            "cve": cve,
            "kev": True,
            "kev_added": v.get("dateAdded"),
            "kev_ransomware": v.get("knownRansomwareCampaignUse"),
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "name": v.get("vulnerabilityName"),
            "due": v.get("dueDate"),
        }


def load_index(path: Path) -> Dict[str, Dict[str, object]]:
    return {r["cve"]: r for r in parse(path)}
