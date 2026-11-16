"""Nuclei templates 解析器（MIT，可再分发）。

只读 YAML，提取：
  - cve-id / name / severity / cvss / cpe / vendor / product / tags
  - 可执行请求 -> 最小步骤（转 curl）
  - matchers -> 预期 marker
不复制模板全文进卡（§4.4），卡内只留 poc_code（<=1.5KB）或 poc_path。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from .common import CardDraft

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

REQ_KINDS = ("http", "network", "tcp", "dns", "ssl", "javascript", "headless", "file")
MAX_CODE = 1400  # 留余量，卡内 poc_code 硬限 1536B


def _load(path: Path):
    if yaml is None:
        return None
    try:
        d = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    return d if isinstance(d, dict) else None


def _cpe_parts(cpe: Optional[str]) -> tuple:
    """cpe:2.3:a:vendor:product:version:... -> (vendor, product)"""
    if not cpe or not cpe.startswith("cpe:"):
        return None, None
    p = cpe.split(":")
    if len(p) > 5:
        vendor = p[3] if p[3] not in ("*", "-") else None
        product = p[4] if p[4] not in ("*", "-") else None
        return vendor, product
    return None, None


def _versions_from_name(name: str) -> List[str]:
    """从 'SaltStack <=3002 - Shell Injection' 这类标题里抽版本约束。"""
    out = []
    for m in re.finditer(r"(<=\s*\d[\w.]*|<\s*\d[\w.]*|>=\s*\d[\w.]*|>\s*\d[\w.]*|\d+\.\d+(?:\.\d+)*\s*(?:to|through|-)\s*\d+\.\d+(?:\.\d+)*)", name):
        v = m.group(1).strip()
        if " to " in v or " through " in v:
            lo, hi = re.split(r"\s*(?:to|through)\s*", v)
            out.append(f">= {lo}, <= {hi}")
        elif re.search(r"\s-\s", v):
            lo, hi = re.split(r"\s-\s", v, 1)
            out.append(f">= {lo}, <= {hi}")
        else:
            out.append(v)
    return list(dict.fromkeys(out))[:3]


def _http_to_curl(block: dict) -> Optional[str]:
    """把一个 http: 条目转成单条 curl 命令。"""
    method = str(block.get("method") or "GET").upper()
    path = block.get("path")
    if isinstance(path, list):
        path = path[0] if path else None
    body = block.get("body")
    headers = block.get("headers") or {}

    raw = block.get("raw")
    if isinstance(raw, list) and raw:
        text = str(raw[0])
        first = text.split("\n", 1)[0].strip()
        m = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)", first)
        if m:
            method, path = m.group(1), m.group(2)
        # 从 raw 里抽 Host / headers / body
        lines = text.splitlines()
        hdrs = []
        i = 1
        while i < len(lines) and lines[i].strip():
            hdrs.append(lines[i].strip())
            i += 1
        body = "\n".join(lines[i + 1:]).strip() if i < len(lines) else None
        headers = {"__raw__": hdrs} if hdrs else {}
    elif not path:
        return None

    if isinstance(path, str) and not path.startswith("{{BaseURL}}"):
        path = "{{BaseURL}}" + (path if path.startswith("/") else "/" + path)
    url = str(path).replace("{{BaseURL}}", "{{BaseURL}}").replace("{{Hostname}}", "{{Hostname}}")
    # 模板变量保留占位，读卡的人知道要替换

    parts = [f"curl -sS -X {method}" if method != "GET" else "curl -sS"]
    if isinstance(headers, dict) and "__raw__" in headers:
        for h in headers["__raw__"]:
            if ":" in h and not h.lower().startswith("host:") and not h.lower().startswith("content-length"):
                parts.append(f"-H {h!r}")
    elif isinstance(headers, dict):
        for k, v in headers.items():
            parts.append(f"-H '{k}: {v}'")
    if body:
        b = str(body).replace("\n", " ").strip()
        if len(b) > 400:
            b = b[:400] + "..."
        parts.append(f"--data-binary '{b}'")
    parts.append(f"'{url}'")
    cmd = " ".join(parts)
    # 把 payload 变量替换成第一个候选值，让命令可直接复制使用
    payloads = block.get("payloads") or {}
    if isinstance(payloads, dict):
        for k, vals in payloads.items():
            if isinstance(vals, list) and vals:
                cmd = cmd.replace("{{" + str(k) + "}}", str(vals[0]))
    cmd = cmd.replace("{{BaseURL}}", "http://TARGET:PORT").replace("{{Hostname}}", "TARGET:PORT")
    return cmd[:MAX_CODE]


def _markers(block: dict) -> str:
    """从 matchers 里抽可读的预期 marker。"""
    bits: List[str] = []
    for m in (block.get("matchers") or []):
        if not isinstance(m, dict):
            continue
        t = m.get("type")
        if t == "status":
            bits.append("HTTP " + "/".join(str(s) for s in (m.get("status") or [])))
        elif t == "word":
            words = m.get("words") or []
            if words:
                part = m.get("part") or "body"
                bits.append(f"{part} 含 " + " 或 ".join(str(w) for w in words[:3]))
        elif t == "regex":
            r = m.get("regex") or []
            if r:
                bits.append(f"{m.get('part') or 'body'} 匹配 {str(r[0])[:60]}")
        elif t == "dsl":
            d = m.get("dsl") or []
            if d:
                bits.append(f"dsl: {str(d[0])[:50]}")
    return "；".join(bits)[:200]


_FP_GENERIC = {
    "server", "via", "etag", "x-cache", "set-cookie", "content-type", "host",
    "cookie", "user-agent", "date", "connection", "keep-alive", "http", "https",
    "content-length", "accept", "accept-encoding", "accept-language",
}


def _fingerprints(d: dict) -> List[str]:
    """从 nuclei 模板抽可用于识别组件的 token：header 名/值、matcher 词、静态路径。"""
    out: List[str] = []
    blocks = d.get("http")
    if isinstance(blocks, dict):
        blocks = [blocks]
    for b in (blocks or []):
        if not isinstance(b, dict):
            continue
        headers = b.get("headers") or {}
        if isinstance(headers, dict):
            for k, v in headers.items():
                if k.startswith("__"):
                    continue
                if len(str(k)) >= 4 and "{{" not in str(k):
                    out.append(str(k))
                if len(str(v)) <= 60 and "{{" not in str(v) and str(v).strip():
                    out.append(str(v))
        paths = b.get("path")
        if isinstance(paths, str):
            paths = [paths]
        for p in (paths or []):
            p = str(p)
            if "{{" in p:
                p = p.split("{{", 1)[0]
            p = p.strip()
            if len(p) >= 4 and p.startswith("/"):
                out.append(p)
                seg = re.match(r"/[A-Za-z0-9_.\-]{2,}/", p)
                if seg:
                    out.append(seg.group(0))
        for m in (b.get("matchers") or []):
            if not isinstance(m, dict):
                continue
            if str(m.get("part") or "").lower() == "header":
                for w in (m.get("words") or [])[:3]:
                    out.append(str(w))
    # 去重、去泛词、限长
    clean: List[str] = []
    for s in out:
        s = re.sub(r"\s+", " ", str(s).strip().lower())
        if not s or s in _FP_GENERIC or len(s) < 4:
            continue
        if re.fullmatch(r"[\d.\-_/]+", s):
            continue
        if s not in clean:
            clean.append(s)
    return clean[:6]


def parse_template(path: Path) -> Optional[CardDraft]:
    d = _load(path)
    if not d:
        return None
    info = d.get("info") or {}
    cls = info.get("classification") or {}
    cves = cls.get("cve-id") or []
    if isinstance(cves, str):
        cves = [cves]
    cves = [str(c).upper() for c in cves if str(c).upper().startswith("CVE-")]
    if not cves:
        return None

    name = str(info.get("name") or d.get("id") or cves[0])
    meta = info.get("metadata") or {}
    vendor = meta.get("vendor")
    product = meta.get("product")
    if not product:
        v2, p2 = _cpe_parts(cls.get("cpe"))
        vendor, product = vendor or v2, p2

    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    tags = [str(t).lower() for t in tags if t]
    # nuclei 的 tags 里 cveXXXX/kev/vuln 这类不是攻击面，过滤掉
    tags = [t for t in tags if not re.fullmatch(r"cve\d*|kev|vkev|vuln|cve", t)][:8]

    marker_bits = []
    step_bits = []
    poc_type = None
    for kind in REQ_KINDS:
        blocks = d.get(kind)
        if not blocks:
            continue
        if isinstance(blocks, dict):
            blocks = [blocks]
        for b in blocks:
            if not isinstance(b, dict):
                continue
            if kind == "http":
                cmd = _http_to_curl(b)
                if cmd:
                    step_bits.append(cmd)
                    poc_type = poc_type or "curl"
            else:
                # 非 http：给出协议级说明，不伪造命令
                step_bits.append(f"按 {kind} 协议发送模板定义的探测包")
                poc_type = poc_type or kind
            mk = _markers(b)
            if mk:
                marker_bits.append(mk)
            if len(step_bits) >= 2:
                break
        if step_bits:
            break

    steps = "\n".join(step_bits)
    if steps and len(steps.encode()) > 600:
        steps = steps[:600]
    marker = "；".join(dict.fromkeys(marker_bits))[:200]

    desc = re.sub(r"\s+", " ", str(info.get("description") or "")).strip()

    rel = None
    try:
        rel = str(path).split("kb/raw/nuclei/", 1)[-1]
    except Exception:
        rel = None

    return CardDraft(
        cve=cves[0],
        title=name[:160],
        aliases=[str(d.get("id") or "")] if d.get("id") and str(d.get("id")).upper() != cves[0] else [],
        vendor=(str(vendor).lower() if vendor else None),
        product=(str(product).lower().replace("_", "-") if product else None),
        versions=_versions_from_name(name),
        fingerprint=_fingerprints(d),
        tags=sorted(set(tags)),
        attack_surface=["http"] if "http" in d else ([k for k in REQ_KINDS if k in d][:1] or ["http"]),
        poc=[{"type": "nuclei", "path": rel or "", "source": "nuclei"}],
        # 有可执行请求但未在目标上验证过 -> candidate
        confidence="candidate",
        source=["nuclei"],
        description=desc[:600],
        steps=steps,
        marker=marker,
    )


def parse_tree(root: Path, limit: int = 0) -> Iterator[CardDraft]:
    n = 0
    for p in sorted(root.rglob("*.yaml")):
        if ".git" in p.parts or p.name.startswith("."):
            continue
        d = parse_template(p)
        if d is None:
            continue
        yield d
        n += 1
        if limit and n >= limit:
            return
