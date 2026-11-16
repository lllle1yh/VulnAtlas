"""把 POC 原文落到 kb/artifacts/<CVE>/（§4.4 / §8.1 render 阶段）。

只落"必要且可再分发"的内容：
  - nuclei 模板：裁掉 references/matchers 之外的大段文字，保留可执行部分
  - 其它源：无本地原文时**不伪造** poc_path
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from .. import paths
from ..card import Card, SECTIONS

MAX_ARTIFACT_BYTES = 1024 * 1024
NUCLEI_KEEP_KEYS = ("id", "info", "http", "network", "tcp", "dns", "ssl",
                    "javascript", "headless", "variables", "flow")


def _trim_nuclei_yaml(text: str) -> str:
    """nuclei 模板裁剪：去掉 digest 注释和超长 reference，保留可执行主体。"""
    lines = []
    skip_refs = False
    for line in text.splitlines():
        if line.startswith("# digest:"):
            continue
        if re.match(r"^\s+reference:\s*$", line):
            skip_refs = True
            lines.append("    reference: []  # stripped by vuln-atlas")
            continue
        if skip_refs:
            if re.match(r"^\s+-\s+", line):
                continue
            skip_refs = False
        lines.append(line)
    out = "\n".join(lines)
    # 去掉 matcher 里的二进制不可打印字节
    out = "".join(ch if (ch == "\n" or ch == "\t" or 32 <= ord(ch) < 127 or ord(ch) > 127) else "" for ch in out)
    return out


def materialize(card: Card, raw_root: Optional[Path] = None) -> Optional[str]:
    """尝试为卡片落 artifact，返回最终 poc_path（失败返回 None）。"""
    raw_root = raw_root or paths.raw_dir()
    src_rel = None
    for p in (card.source or []):
        pass
    # 从 poc_path 反推源文件：nuclei 的规范名是 nuclei-<原文件名>.yaml
    if not card.poc_path:
        return None
    if card.poc_path.startswith("artifacts/"):
        base = Path(card.poc_path).name
    else:
        base = Path(card.poc_path).name
    name = base
    if name.startswith("nuclei-"):
        name = name[len("nuclei-"):]
    elif name.startswith("edb-"):
        return None  # 未下载 exploit 原文，不伪造

    candidates = list(raw_root.glob(f"nuclei/**/{name}"))
    if not candidates:
        return None
    src = candidates[0]
    if src.stat().st_size > MAX_ARTIFACT_BYTES:
        return None

    dest_dir = paths.artifacts_dir() / card.id
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / base
    try:
        text = src.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    dest.write_text(_trim_nuclei_yaml(text), encoding="utf-8")
    rel = f"artifacts/{card.id}/{base}"
    return rel


def materialize_github_meta(card: Card, raw_root: Optional[Path] = None) -> Optional[str]:
    """把 PoC-in-GitHub 的仓库元数据落成本地证据文件（不含外链、不含源码）。

    §4.0：卡片不能依赖联网链接；这里只写 repo 名/语言/star/描述，
    让 agent 在离线状态下知道"存在哪些 PoC、用什么语言"。
    """
    if "github-poc" not in (card.source or []) or not card.cve:
        return None
    raw_root = raw_root or paths.raw_dir()
    cands = list(raw_root.glob(f"github-poc/*/{card.cve}.json"))
    if not cands:
        return None
    try:
        repos = json.loads(cands[0].read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(repos, list) or not repos:
        return None
    lines = [
        "# GitHub PoC 元数据（未下载源码；仅用于离线识别）",
        "# 本文件不是可执行 PoC；复现必须另行取得源码并验证。",
    ]
    for r in repos[:10]:
        if not isinstance(r, dict):
            continue
        full = str(r.get("full_name") or r.get("name") or "").strip()
        if not full:
            continue
        lang = str(r.get("language") or "-")
        stars = int(r.get("stargazers_count") or 0)
        desc = re.sub(r"\s+", " ", str(r.get("description") or ""))[:160]
        lines.append(f"- {full} | language={lang} | stars={stars} | {desc}".rstrip())
    if len(lines) <= 2:
        return None
    text = "\n".join(lines) + "\n"
    dest_dir = paths.artifacts_dir() / card.id
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "github-poc-index.txt"
    dest.write_text(text[: MAX_ARTIFACT_BYTES], encoding="utf-8")
    return f"artifacts/{card.id}/github-poc-index.txt"


def apply(card: Card) -> Card:
    """落 artifact 并把 poc_path 改成真实路径；落不下来就清空 poc_path。

    注意：
      - `poc_code`（如 Metasploit module 指针）是卡内可执行内容，不因没有本地文件而清空；
      - GitHub-PoC 卡没有源码，落一个本地元数据证据文件：poc_path 指向它，
        poc_type 记为 github-poc，但置信度保持 unverified（排序不加 POC_BONUS）。
    """
    rel = materialize(card)
    secs = card.sections()
    if rel:
        card.poc_path = rel
        secs["证据指针"] = f"本地证据：{rel}"
    else:
        card.poc_path = None
        if card.poc_code:
            secs["证据指针"] = "本地证据：卡内 poc_code（Metasploit module 指针）"
        else:
            gh = materialize_github_meta(card)
            if gh:
                card.poc_path = gh
                card.poc_type = card.poc_type or "github-poc"
                secs["证据指针"] = f"本地证据：{gh}（GitHub PoC 元数据，非源码）"
            else:
                secs["证据指针"] = "本地证据：无（仅元数据卡）"
        if card.confidence == "verified":
            card.confidence = "candidate"
    card.set_sections(secs)
    return card
