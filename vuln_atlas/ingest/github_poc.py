"""PoC-in-GitHub 解析器（CC0-1.0）。

每个 CVE 一个 JSON：GitHub 仓库搜索结果数组。
只取元数据（repo 名/描述/语言/stars/创建时间）作为 POC 存在性证据，
不把外链写进卡片正文（§4.0），只用于：提升 confidence + 记录 POC 数量。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, List, Optional

from .common import CardDraft


def _load(path: Path) -> Optional[List[dict]]:
    try:
        d = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    return d if isinstance(d, list) else None


def parse_file(path: Path) -> Optional[CardDraft]:
    cve = path.stem.upper()
    if not cve.startswith("CVE-"):
        return None
    repos = _load(path)
    if not repos:
        return None
    # 只保留非 fork、有描述或有 star 的
    good = []
    for r in repos:
        if not isinstance(r, dict):
            continue
        if r.get("fork"):
            continue
        good.append(r)
    if not good:
        return None

    langs = sorted({str(r.get("language")) for r in good if r.get("language")})
    names = [str(r.get("full_name") or r.get("name") or "") for r in good if r.get("full_name") or r.get("name")]
    stars = sum(int(r.get("stargazers_count") or 0) for r in good)
    latest = max((str(r.get("pushed_at") or "") for r in good), default="")

    descs = [str(r.get("description")) for r in good if r.get("description")]
    note = f"GitHub 公开 PoC 仓库 {len(good)} 个"
    if langs:
        note += f"，语言 {'/'.join(langs[:3])}"
    if stars:
        note += f"，累计 star {stars}"

    return CardDraft(
        cve=cve,
        title=next((d[:120] for d in descs), f"{cve} GitHub PoC"),
        # 仓库名（owner/repo）不进 aliases：它们是 FTS 索引列，
        # 会让 "public-passwd" 这类名字污染检索（实测把 httpd 路径穿越卡挤出前 300）。
        # 仓库清单会落到 artifacts/<CVE>/github-poc-index.txt（见 artifacts.py）。
        aliases=[],
        tags=[l.lower() for l in langs[:4]],
        poc=[{"type": "github-poc", "path": "", "source": "github-poc"}],
        confidence="unverified",
        source=["github-poc"],
        description=note,
        steps=(
            "本卡仅有公开 GitHub PoC 仓库的存在性元数据，未包含 PoC 源码，不能直接复现。\n"
            "1. 先用本卡确认受影响产品/版本。\n"
            "2. 需要复现时，优先使用库内 Nuclei / ExploitDB / Vulhub 步骤。\n"
            "3. 若只有 GitHub 来源，需另行取得源码并在实验环境验证；本卡不作为可执行依据。"
        ),
        marker="无（仅元数据；未下载 PoC 源码，不能作为验证依据）",
    )


def parse_tree(root: Path, limit: int = 0) -> Iterator[CardDraft]:
    n = 0
    for p in sorted(root.rglob("CVE-*.json")):
        if ".git" in p.parts:
            continue
        d = parse_file(p)
        if d is None:
            continue
        yield d
        n += 1
        if limit and n >= limit:
            return
