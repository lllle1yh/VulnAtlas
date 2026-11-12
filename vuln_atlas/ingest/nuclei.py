from __future__ import annotations

import re
from pathlib import Path

import yaml

from vuln_atlas.db import upsert_card

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def card_from_template(path: Path, root: Path) -> dict | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    info = data.get("info") or {}
    if not isinstance(info, dict):
        return None
    name = str(info.get("name") or data.get("id") or path.stem)
    classification = info.get("classification") or {}
    cve_ids = _list(classification.get("cve-id"))
    if not cve_ids:
        cve_ids = [match.group(0).upper() for match in CVE_RE.finditer(name)]
    cve = cve_ids[0].upper() if cve_ids else None
    card_id = cve or str(data.get("id") or path.stem)
    tags = []
    raw_tags = info.get("tags")
    if isinstance(raw_tags, str):
        tags = [item.strip() for item in raw_tags.split(",") if item.strip()]
    else:
        tags = _list(raw_tags)
    references = _list(info.get("reference"))
    description = str(info.get("description") or "")
    steps = (
        f"nuclei template: {data.get('id') or path.stem}\n"
        f"运行: nuclei -t {path.relative_to(root).as_posix()} -u TARGET"
    )
    marker = "nuclei 命中模板（matchers 满足）"
    body = "\n\n".join(
        part for part in [
            f"# {name}",
            description,
            "## 模板路径",
            path.relative_to(root).as_posix(),
            "## 参考",
            "\n".join(references),
        ] if part
    )
    return {
        "id": card_id,
        "cve": cve,
        "title": name,
        "aliases": [str(data.get("id") or ""), *cve_ids],
        "vendor": None,
        "product": None,
        "versions": [],
        "fingerprint": [],
        "tags": tags,
        "attack_surface": ["http"],
        "poc_type": "nuclei",
        "poc_path": str(path.relative_to(root)),
        "steps": steps,
        "marker": marker,
        "confidence": "candidate",
        "last_verified": None,
        "source": ["nuclei-templates"],
        "body": body,
    }


def ingest_nuclei(conn, root: str | Path) -> dict:
    root = Path(root)
    files = 0
    cards = 0
    skipped = 0
    for path in root.rglob("*.yaml"):
        files += 1
        card = card_from_template(path, root)
        if card is None:
            skipped += 1
            continue
        upsert_card(conn, card)
        cards += 1
    conn.commit()
    return {"files": files, "cards": cards, "skipped": skipped}
