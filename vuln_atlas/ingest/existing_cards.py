"""现有 knowledges 卡解析器：把外部 md 清洗成本仓库卡片（§3.3 / §15 第 2 条）。"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, List, Optional

from ..card import card_from_text, Card, SECTIONS
from .common import CardDraft

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CN_SECTION_ALIASES = {
    "目标特征 / 版本": ["目标特征", "指纹", "版本影响", "影响版本", "受影响版本", "漏洞影响"],
    "前置条件": ["前置条件", "前提条件", "利用条件", "环境要求"],
    "最小步骤": ["最小步骤", "复现步骤", "利用步骤", "poc", "POC", "payload", "利用过程"],
    "预期 marker": ["预期 marker", "预期结果", "验证", "回显", "特征回显"],
    "证据指针": ["证据", "截图", "证据指针"],
    "失败模式 / 不适用条件": ["失败模式", "不适用", "修复", "限制"],
}


def _norm(text: str) -> str:
    return text.replace("\r\n", "\n")


def extract_sections(md: str) -> dict:
    """把任意标题层级映射到六段；`#`/`##`/`###` 都接受。"""
    md = _norm(md)
    raw: dict = {}
    cur = None
    buf: List[str] = []
    for line in md.splitlines():
        m = re.match(r"^#{1,4}\s+(.+?)\s*$", line)
        if m:
            if cur is not None:
                raw[cur] = "\n".join(buf).strip()
            cur, buf = m.group(1).strip(), []
        elif cur is not None:
            buf.append(line)
    if cur is not None:
        raw[cur] = "\n".join(buf).strip()

    out = {k: "" for k in SECTIONS}
    for title, content in raw.items():
        for canon, keys in CN_SECTION_ALIASES.items():
            if any(k.lower() in title.lower() for k in keys) and not out[canon]:
                out[canon] = content
                break
    return out


def parse_file(path: Path) -> Optional[CardDraft]:
    text = _norm(path.read_text(encoding="utf-8", errors="replace"))
    cve = None
    first = text.lstrip().split("\n", 1)[0]
    m = CVE_RE.search(first) or CVE_RE.search(text[:400])
    if m:
        cve = m.group(0).upper()

    title = ""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            title = s.lstrip("#").strip()
            break
        if s and not s.startswith("---"):
            title = s[:120]
            break
    if not title:
        title = cve or path.stem

    secs = extract_sections(text)
    body_chars = sum(len(v) for v in secs.values())
    if body_chars < 40:
        return None  # 内容太少，不可复核

    tags = []
    low = text.lower()
    for tag, words in (
        ("rce", ["rce", "命令执行", "代码执行", "command injection"]),
        ("lfi", ["lfi", "文件包含", "路径穿越", "任意文件读取"]),
        ("sqli", ["sql 注入", "sqli"]),
        ("deserialization", ["反序列化"]),
        ("upload", ["上传"]),
        ("auth", ["越权", "绕过", "未授权", "弱口令"]),
        ("ssrf", ["ssrf"]),
        ("xss", ["xss", "跨站"]),
    ):
        if any(w in low for w in words):
            tags.append(tag)

    return CardDraft(
        cve=cve,
        title=title[:160],
        aliases=[path.stem] if path.stem.upper() != (cve or "") else [],
        tags=tags,
        attack_surface=["http"] if "http" in low or "curl" in low else [],
        confidence="candidate",
        source=["existing-knowledges"],
        description=secs.get("目标特征 / 版本", "")[:300],
        steps=secs.get("最小步骤", "")[:600],
        marker=secs.get("预期 marker", "")[:200],
    )


def parse_tree(root: Path, limit: int = 0) -> Iterator[CardDraft]:
    n = 0
    for p in sorted(root.rglob("*.md")):
        if any(part.startswith(".") for part in p.parts):
            continue
        d = parse_file(p)
        if d is None:
            continue
        yield d
        n += 1
        if limit and n >= limit:
            return
