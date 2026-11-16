"""Metasploit 解析器：只索引 module 路径与 references 中的 CVE，不复制代码。"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterator

from .common import CardDraft

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def parse_metadata(path: Path) -> Iterator[CardDraft]:
    """path 为 module_cves.json / modules_metadata_base.json（name -> {references: [...]}）。

    §3.2：只索引 module 路径与 references 中的 CVE，不复制 Ruby 源码。
    module 路径写入 `poc_code`（<=1.5KB），不伪造本地 artifact 路径。
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.items() if isinstance(data, dict) else ((m.get("name", ""), m) for m in data)
    for name, meta in items:
        refs = (meta or {}).get("references") or []
        refs = [str(r) for r in refs]
        # 本地快照 module_cves.json 的结构是 {"cves": [...]}；
        # 上游 modules_metadata_base.json 才是 {"references": [...]}，两者都支持。
        cves = {str(c).upper() for c in ((meta or {}).get("cves") or [])}
        cves.update(m.upper() for r in refs for m in CVE_RE.findall(r))
        cves = sorted(c for c in cves if c.startswith("CVE-"))
        if not cves:
            continue
        module = str(name)
        # 去掉 modules/ 前缀，保留 exploit/auxiliary/... 路径
        display = module[len("modules/"):] if module.startswith("modules/") else module
        display = display[:-3] if display.endswith(".rb") else display
        code = f"use {display}\nset RHOSTS TARGET\nset RPORT PORT\nrun"
        title = str((meta or {}).get("name") or display.replace("/", " "))[:200]
        for cve in cves:
            yield CardDraft(
                cve=cve,
                title=title,
                aliases=[],
                poc=[{"type": "msf", "path": "", "code": code, "source": "metasploit"}],
                confidence="candidate",
                source=["metasploit"],
                description=str((meta or {}).get("description") or "")[:300],
                steps=code,
                poc_code=code,
            )


def parse_tree(root: Path, limit: int = 0) -> Iterator[CardDraft]:
    """优先解析快照 module_cves.json；没有时兜底扫 ruby 模块里的 references。"""
    meta = root / "module_cves.json"
    if meta.exists():
        n = 0
        for d in parse_metadata(meta):
            yield d
            n += 1
            if limit and n >= limit:
                return
        return

    n = 0
    for p in sorted(root.rglob("*.rb")):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "CVE-" not in text:
            continue
        cves = sorted({m.upper() for m in CVE_RE.findall(text)})
        module = str(p.relative_to(root)).replace("\\", "/")
        display = module[len("modules/"):] if module.startswith("modules/") else module
        display = display[:-3] if display.endswith(".rb") else display
        code = f"use {display}\nset RHOSTS TARGET\nset RPORT PORT\nrun"
        for cve in cves:
            yield CardDraft(
                cve=cve,
                title=p.stem.replace("_", " ")[:120],
                poc=[{"type": "msf", "path": "", "code": code, "source": "metasploit"}],
                confidence="candidate",
                source=["metasploit"],
                steps=code,
                poc_code=code,
            )
            n += 1
        if limit and n >= limit:
            return
