"""PayloadsAllTheThings 解析器（MIT，可再分发）。

按 §8.3：没有 CVE 且没有可执行 POC 的内容不入库。
因此这里**只处理以单个 CVE 为主题的章节/文件**，其余通用手法卡一律跳过。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, List, Optional

from .common import CardDraft

CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.I)
ANY_SEC = re.compile(r"^(#{1,3})\s+(.+)$", re.M)
CMD_HINT = re.compile(r"(curl\s|wget\s|nc\s|python3?\s|java\s+-jar|payload=|POST\s+/|GET\s+)", re.I)


def _sections(text: str):
    marks = [(m.start(), len(m.group(1)), m.group(2).strip()) for m in ANY_SEC.finditer(text)]
    out = []
    for i, (pos, lvl, title) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        out.append((lvl, title, text[pos:end]))
    return out


def _steps_from(body: str) -> str:
    cmds: List[str] = []
    for b in re.findall(r"```[a-zA-Z0-9]*\n(.*?)```", body, re.S):
        for line in b.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and CMD_HINT.search(s):
                cmds.append(s)
    if not cmds:
        for line in body.splitlines():
            s = line.strip().strip("`")
            if s.startswith(("curl ", "http://", "https://")) and len(s) < 300:
                cmds.append(s)
    return "\n".join(f"{i}. {c}" for i, c in enumerate(cmds[:5], 1))


def parse_file(path: Path) -> Iterator[CardDraft]:
    text = path.read_text(encoding="utf-8", errors="replace")
    rel = path.name
    try:
        rel = str(path).split("PayloadsAllTheThings/", 1)[-1]
    except Exception:
        pass

    # 情形 A：整个文件就是某个 CVE（标题含 CVE）
    h1 = None
    for m in re.finditer(r"^#\s+(.+)$", text, re.M):
        h1 = m.group(1)
        break
    if h1 and CVE_RE.search(h1):
        cve = CVE_RE.search(h1).group(1).upper()
        steps = _steps_from(text)
        if not steps:
            return
        yield CardDraft(
            cve=cve,
            title=re.sub(r"\s*CVE-\d{4}-\d{4,7}\s*", " ", h1).strip()[:160] or cve,
            aliases=[h1[:100]],
            versions=[],
            tags=[],
            attack_surface=["http"],
            poc=[{"type": "payloads", "path": rel, "source": "payloads"}],
            confidence="candidate",
            source=["payloads"],
            description=re.sub(r"\s+", " ", text.split("\n## ", 1)[0].replace("#", " ")).strip()[:400],
            steps=steps,
            marker="按 PoC 请求后出现预期回显（文件内容 / 命令输出 / 报错特征）",
        )
        return

    # 情形 B：章节标题含 CVE（如 "### CVE-2019-9726"）
    for lvl, title, body in _sections(text):
        m = CVE_RE.search(title)
        if not m:
            continue
        steps = _steps_from(body)
        if not steps:
            continue
        yield CardDraft(
            cve=m.group(1).upper(),
            title=re.sub(r"\s*CVE-\d{4}-\d{4,7}\s*", " ", title).strip()[:160] or m.group(1),
            aliases=[title[:100]],
            versions=[],
            tags=[],
            attack_surface=["http"],
            poc=[{"type": "payloads", "path": rel, "source": "payloads"}],
            confidence="candidate",
            source=["payloads"],
            description=title[:300],
            steps=steps,
            marker="按 PoC 请求后出现预期回显",
        )


def parse_tree(root: Path, limit: int = 0) -> Iterator[CardDraft]:
    n = 0
    for p in sorted(root.rglob("*.md")):
        if ".git" in p.parts:
            continue
        for d in parse_file(p):
            yield d
            n += 1
            if limit and n >= limit:
                return
