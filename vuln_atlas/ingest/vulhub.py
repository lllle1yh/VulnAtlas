"""Vulhub README 解析器（MIT，可再分发）。

结构：<component>/<CVE-xxxx-yyyy>/README.md
README 里有：漏洞描述、环境搭建（docker compose）、可执行 POC（curl/http 请求）。
只提取「最小步骤」与「预期 marker」，不复制整篇 README（§4.4）。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, List, Optional

from .common import CardDraft

CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.I)
SEC_ENV = re.compile(r"^##+\s*(environment\s*setup|vulnerable\s*environment|"
                     r"vulnerability\s*environment|setup|"
                     r"start\s*vulnerability\s*application|vulnerable\s*application)\s*$", re.I | re.M)
SEC_POC = re.compile(r"^##+\s*(poc|exploit|vulnerability\s*reproduction?|vulnerability\s*exploitation|"
                     r"exploitation)\s*$", re.I | re.M)
ANY_SEC = re.compile(r"^##+\s+.+$", re.M)

# 明显的指令型命令（curl / http 请求 / 编译运行）
CMD_HINT = re.compile(r"(curl\s|wget\s|nmap\s|python3?\s|java\s+-jar|go\s+run|"
                      r"docker\s+compose|nc\s|\$\s|POST\s+/|GET\s+/|payload=)", re.I)
URL_IN_TEXT = re.compile(r"https?://[^\s)\]>\"'`,，。；）]+", re.I)


def _sections(text: str) -> list:
    """切成 [(title, body)]。"""
    marks = [(m.start(), m.group(0)) for m in ANY_SEC.finditer(text)]
    out = []
    for i, (pos, title) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        out.append((title.strip("# \t"), text[pos + len(title):end].strip()))
    return out


def _extract_steps(text: str) -> str:
    """从 POC/Reproduction 段提取可执行步骤（代码块 + 命令行）。"""
    secs = _sections(text)
    poc_body = ""
    for title, body in secs:
        if re.search(r"(poc|exploit|reproduc|exploitation)", title, re.I):
            poc_body = body
            break
    if not poc_body:
        # 没有明确 POC 段时，退化为全文找命令
        poc_body = text

    # 抽代码块
    blocks = re.findall(r"```[a-zA-Z0-9]*\n(.*?)```", poc_body, re.S)
    cmds: List[str] = []
    for b in blocks:
        for line in b.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if CMD_HINT.search(line) or line.startswith(("curl", "POST", "GET", "http")):
                cmds.append(line)
    # 代码块里没有可执行命令时，抽正文内联代码（反引号）和裸 URL 行
    if not cmds:
        for line in poc_body.splitlines():
            # 反引号内联代码里常是完整请求 URL
            for inline in re.findall(r"`([^`\n]{10,400})`", line):
                cand = inline.strip()
                if cand.startswith(("curl ", "http://", "https://", "POST ", "GET ")) \
                        or re.search(r"(locale=|\?.*=|cmd=|file=)", cand):
                    cmds.append(cand)
            s2 = line.strip().strip("`").strip()
            if s2.startswith(("curl ", "http://", "https://")) and len(s2) < 400:
                cmds.append(s2)
    if not cmds:
        return ""
    steps = []
    for i, c in enumerate(cmds[:6], 1):
        steps.append(f"{i}. {c}")
    return "\n".join(steps)


def _extract_marker(text: str) -> str:
    """预期 marker：README 里常写"看到 xxx 即为成功"。"""
    pats = [
        r"(?:you\s+(?:will|can)\s+see|成功(?:后|则|时)?(?:会)?(?:看到|显示)|若.*?则.*?成功|"
        r"indicates?|proof\s+of|you\s+should\s+see)[^\n]{5,160}",
    ]
    for p in pats:
        m = re.search(p, text, re.I)
        if m:
            return m.group(0).strip()[:200]
    # 退化：从 POC 段找 root:x:0:0 / uid=0 这类典型 marker
    low = text.lower()
    if "root:x:0:0" in text or "/etc/passwd" in low:
        return "响应中出现 root:x:0:0（任意文件读取成功）"
    if "uid=0" in text or "whoami" in low or "id;" in low:
        return "响应中出现 uid=0 或命令回显（命令执行成功）"
    if "flag{" in low:
        return "响应中出现 flag{...}"
    # 退化：取 POC 段里第一个"Read/Get/访问"类的描述
    m = re.search(r"(?:read|get|访问|读取)[^\n]{5,100}", text, re.I)
    if m:
        return m.group(0).strip()[:200]
    return ""


def _extract_version(text: str, title: str) -> List[str]:
    """从标题和描述里抽版本约束。"""
    out = []
    for src in (title, text[:1500]):
        for m in re.finditer(r"(?:<=|>=|<|>)\s*\d+(?:\.\d+){1,3}", src):
            out.append(m.group(0).replace(" ", ""))
        for m in re.finditer(r"(\d+(?:\.\d+){1,3})\s*(?:to|through|至|and earlier|及更早)", src):
            out.append(f"<= {m.group(1)}")
    return list(dict.fromkeys(out))[:3]


def parse_file(path: Path) -> Optional[CardDraft]:
    text = path.read_text(encoding="utf-8", errors="replace")
    parts = path.parts
    cve = None
    for p in reversed(parts):
        m = CVE_RE.fullmatch(p)
        if m:
            cve = m.group(1).upper()
            break
    if not cve:
        m = CVE_RE.search(path.parent.name) or CVE_RE.search(text[:300])
        if not m:
            return None
        cve = m.group(1).upper()

    title = ""
    for line in text.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            break
    if not title:
        title = cve

    # component = 样例目录名（如 coldfusion / activemq）
    comp = path.parent.parent.name if len(parts) >= 2 else None

    steps = _extract_steps(text)
    marker = _extract_marker(text)
    versions = _extract_version(text, title)

    desc = re.sub(r"\s+", " ", text.split("\n## ", 2)[0].replace("#", " ")).strip()[:400]

    rel = None
    try:
        idx = str(path).index("kb/raw/vulhub/")
        rel = str(path)[idx + len("kb/raw/vulhub/"):]
    except ValueError:
        rel = path.name

    return CardDraft(
        cve=cve,
        title=re.sub(r"\s*\(CVE-\d{4}-\d{4,7}\)\s*", " ", title).strip()[:160] or cve,
        vendor=None,
        product=(comp.lower() if comp else None),
        versions=versions,
        tags=[],
        attack_surface=["http"] if ("http://" in text or "curl" in text.lower()) else ["network"],
        poc=[{"type": "vulhub", "path": rel, "source": "vulhub"}],
        confidence="candidate",
        source=["vulhub"],
        description=desc,
        steps=steps,
        marker=marker,
    )


def parse_tree(root: Path, limit: int = 0) -> Iterator[CardDraft]:
    n = 0
    for p in sorted(root.rglob("README.md")):
        if ".git" in p.parts:
            continue
        d = parse_file(p)
        if d is None:
            continue
        yield d
        n += 1
        if limit and n >= limit:
            return
