"""NVD CVE 2.0 解析器：json.gz -> CardDraft（元数据卡，confidence=candidate）。"""
from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Iterator, List, Optional

from .common import CardDraft

# CWE -> 我们的 tag 词表
CWE_TAGS = {
    "CWE-22": "path-traversal", "CWE-77": "command-injection", "CWE-78": "command-injection",
    "CWE-79": "xss", "CWE-89": "sqli", "CWE-94": "rce", "CWE-98": "lfi",
    "CWE-119": "memory-corruption", "CWE-287": "auth", "CWE-306": "auth",
    "CWE-352": "csrf", "CWE-434": "upload", "CWE-502": "deserialization",
    "CWE-611": "xxe", "CWE-787": "memory-corruption", "CWE-918": "ssrf",
    "CWE-1321": "prototype-pollution",
}


def _cp(vendor: Optional[str], product: Optional[str]) -> Optional[str]:
    if not product:
        return None
    return str(product).strip().lower().replace(" ", "-")


def parse(path: Path, limit: Optional[int] = None) -> Iterator[CardDraft]:
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    n = 0
    for item in data.get("vulnerabilities", []):
        cve_obj = item.get("cve", {})
        cve = (cve_obj.get("id") or "").upper()
        if not cve.startswith("CVE-"):
            continue
        desc = ""
        for d in cve_obj.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc:
            continue
        metrics = cve_obj.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if arr:
                cvss = arr[0].get("cvssData", {}).get("baseScore")
                break

        weak = set()
        for w in cve_obj.get("weaknesses", []):
            for d in w.get("description", []):
                tag = CWE_TAGS.get(d.get("value", ""))
                if tag:
                    weak.add(tag)

        vendor = product = None
        versions: List[str] = []
        for cfg in cve_obj.get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    crit = m.get("criteria") or ""
                    parts = crit.split(":")
                    if len(parts) > 4:
                        vendor = vendor or parts[3]
                        product = product or parts[4]
                    if m.get("versionEndExcluding"):
                        versions.append(f"< {m['versionEndExcluding']}")
                    elif m.get("versionEndIncluding"):
                        versions.append(f"<= {m['versionEndIncluding']}")
        versions = list(dict.fromkeys(versions))[:4]

        yield CardDraft(
            cve=cve,
            title=f"{product or '未知组件'} {cve}",
            aliases=[cve.lower()],
            vendor=vendor,
            product=_cp(vendor, product),
            versions=versions,
            tags=sorted(weak),
            attack_surface=["http"],
            confidence="candidate",
            source=["nvd"] + (["kev"] if False else []),
            description=desc[:600],
            steps="",
            marker="",
        )
        n += 1
        if limit and n >= limit:
            return
