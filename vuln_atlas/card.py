"""卡片模型：frontmatter 解析/生成 + 体积与结构校验（§4.2 / §4.4）。"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

# ---- 硬上限（§4.4）----
LIMIT_CARD_BYTES = 8 * 1024
LIMIT_BODY_BYTES = 5 * 1024
LIMIT_FRONTMATTER_BYTES = 1024
LIMIT_POC_CODE_BYTES = 1536
LIMIT_POC_CODE_LINES = 40
LIMIT_ARTIFACTS_BYTES = 1024 * 1024

# 正文固定六段（顺序即渲染顺序）
SECTIONS = [
    "目标特征 / 版本",
    "前置条件",
    "最小步骤",
    "预期 marker",
    "证据指针",
    "失败模式 / 不适用条件",
]

SECTION_LIMIT_CHARS = {
    "目标特征 / 版本": 300,
    "前置条件": 200,
    "最小步骤": 600,
    "预期 marker": 200,
    "证据指针": 150,
    "失败模式 / 不适用条件": 300,
}

CONFIDENCE_LEVELS = ("verified", "candidate", "unverified")

LIST_FIELDS = ("aliases", "versions", "fingerprint", "tags", "attack_surface", "source")


@dataclass
class Card:
    id: str
    title: str
    cve: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    vendor: Optional[str] = None
    product: Optional[str] = None
    versions: List[str] = field(default_factory=list)
    fingerprint: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    attack_surface: List[str] = field(default_factory=list)
    poc_type: Optional[str] = None
    poc_path: Optional[str] = None
    poc_code: Optional[str] = None
    confidence: str = "candidate"
    last_verified: Optional[str] = None
    source: List[str] = field(default_factory=list)
    license: Optional[str] = None
    body: str = ""

    # ---------- 正文 ----------
    def sections(self) -> Dict[str, str]:
        return parse_sections(self.body)

    def section(self, name: str) -> str:
        return self.sections().get(name, "")

    def set_sections(self, mapping: Dict[str, str]) -> None:
        parts = []
        for name in SECTIONS:
            txt = (mapping.get(name) or "").strip()
            parts.append(f"## {name}\n\n{txt}\n")
        self.body = "\n".join(parts)

    def merged_text(self) -> str:
        """用于 FTS 的合并文本（正文 + 关键字段）。"""
        bits = [self.title, self.body]
        bits.extend(self.aliases)
        bits.extend(self.tags)
        bits.extend(self.fingerprint)
        if self.product:
            bits.append(self.product)
        if self.vendor:
            bits.append(self.vendor)
        return "\n".join(b for b in bits if b)


def parse_sections(body: str) -> Dict[str, str]:
    """按 `## 标题` 切分正文。"""
    out: Dict[str, str] = {}
    cur: Optional[str] = None
    buf: List[str] = []
    for line in body.splitlines():
        m = re.match(r"^##\s+(.+?)\s*$", line)
        if m:
            if cur is not None:
                out[cur] = "\n".join(buf).strip()
            cur, buf = m.group(1).strip(), []
        elif cur is not None:
            buf.append(line)
    if cur is not None:
        out[cur] = "\n".join(buf).strip()
    return out


# ---------------- frontmatter ----------------
def split_frontmatter(text: str) -> Tuple[Optional[str], str]:
    """返回 (frontmatter_yaml, body)。没有 frontmatter 时返回 (None, text)。"""
    text = text.replace("\r\n", "\n")
    if not text.startswith("---\n"):
        return None, text
    end = text.find("\n---\n", 3)
    if end == -1:
        return None, text
    body = text[end + 5:]
    if body.startswith("\n"):
        body = body[1:]
    return text[4:end], body


def _try_yaml():
    try:
        import yaml  # type: ignore

        return yaml
    except Exception:  # pragma: no cover - 环境无 PyYAML 时走内置解析器
        return None


def _fallback_load(text: str) -> Dict[str, Any]:
    """只支持本仓库生成的 frontmatter 子集：scalar / inline list / block list / block scalar。"""
    data: Dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        m = re.match(r"^([A-Za-z_][\w\-]*):(?:\s*(.*))?$", line)
        if not m:
            i += 1
            continue
        key, rest = m.group(1), (m.group(2) or "").strip()
        if rest in ("|", "|-", ">", ">-"):
            i += 1
            buf = []
            while i < len(lines) and (lines[i].startswith("  ") or not lines[i].strip()):
                buf.append(lines[i][2:] if lines[i].startswith("  ") else "")
                i += 1
            data[key] = ("\n" if rest.startswith("|") else " ").join(buf).rstrip("\n")
            continue
        if rest == "":
            i += 1
            items = []
            while i < len(lines) and re.match(r"^\s*-\s+", lines[i]):
                items.append(_unquote(lines[i].split("-", 1)[1].strip()))
                i += 1
            data[key] = items if items else None
            continue
        if rest.startswith("[") and rest.endswith("]"):
            inner = rest[1:-1].strip()
            data[key] = [_unquote(x) for x in _split_inline(inner)] if inner else []
            i += 1
            continue
        data[key] = _unquote(rest)
        i += 1
    return data


def _split_inline(s: str) -> List[str]:
    out, buf, quote = [], [], None
    for ch in s:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch == ",":
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        out.append("".join(buf).strip())
    return [x for x in out if x]


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        inner = s[1:-1]
        return inner.replace("\\n", "\n").replace('\\"', '"') if s[0] == '"' else inner.replace("''", "'")
    return s


def load_frontmatter(text: str) -> Tuple[Dict[str, Any], str]:
    fm, body = split_frontmatter(text)
    if fm is None:
        return {}, text
    yaml = _try_yaml()
    if yaml is not None:
        try:
            data = yaml.safe_load(fm) or {}
            if not isinstance(data, dict):
                raise ValueError("frontmatter 不是映射")
            return data, body
        except Exception:
            pass
    return _fallback_load(fm), body


def _scalar(v: Optional[str]) -> str:
    if v is None:
        return '""'
    v = str(v)
    if v == "" or re.search(r'[:#\[\]{}&*!|>\'"%@`]', v) or v.strip() != v or v in ("true", "false", "null", "~"):
        return json.dumps(v, ensure_ascii=False)
    return v


def dump_frontmatter(card: Card) -> str:
    lines = ["---"]
    lines.append(f"id: {_scalar(card.id)}")
    if card.cve:
        lines.append(f"cve: {_scalar(card.cve)}")
    lines.append(f"title: {_scalar(card.title)}")
    for name in LIST_FIELDS:
        vals = getattr(card, name) or []
        if not vals:
            continue
        if len(vals) <= 6 and all(len(v) < 40 and "\n" not in v for v in vals):
            lines.append(f"{name}: [{', '.join(_scalar(v) for v in vals)}]")
        else:
            lines.append(f"{name}:")
            lines.extend(f"  - {_scalar(v)}" for v in vals)
    if card.vendor:
        lines.append(f"vendor: {_scalar(card.vendor)}")
    if card.product:
        lines.append(f"product: {_scalar(card.product)}")
    if card.poc_type:
        lines.append(f"poc_type: {_scalar(card.poc_type)}")
    if card.poc_path:
        lines.append(f"poc_path: {_scalar(card.poc_path)}")
    if card.poc_code:
        lines.append("poc_code: |")
        lines.extend("  " + ln for ln in card.poc_code.rstrip("\n").splitlines())
    lines.append(f"confidence: {_scalar(card.confidence)}")
    if card.last_verified:
        lines.append(f"last_verified: {_scalar(card.last_verified)}")
    if card.license:
        lines.append(f"license: {_scalar(card.license)}")
    lines.append("---")
    return "\n".join(lines) + "\n"


def card_from_text(text: str) -> Card:
    meta, body = load_frontmatter(text)
    return card_from_meta(meta, body)


def card_from_meta(meta: Dict[str, Any], body: str) -> Card:
    def lst(name):
        v = meta.get(name) or []
        if isinstance(v, str):
            return [v]
        return [str(x) for x in v]

    cve = meta.get("cve")
    cve = str(cve).strip().upper() if cve else None
    cid = str(meta.get("id") or cve or "").strip()
    return Card(
        id=cid,
        title=str(meta.get("title") or "").strip(),
        cve=cve,
        aliases=lst("aliases"),
        vendor=(str(meta["vendor"]).strip() if meta.get("vendor") else None),
        product=(str(meta["product"]).strip() if meta.get("product") else None),
        versions=lst("versions"),
        fingerprint=lst("fingerprint"),
        tags=[t.lower() for t in lst("tags")],
        attack_surface=[t.lower() for t in lst("attack_surface")],
        poc_type=(str(meta["poc_type"]).strip() if meta.get("poc_type") else None),
        poc_path=(str(meta["poc_path"]).strip() if meta.get("poc_path") else None),
        poc_code=(str(meta["poc_code"]).rstrip("\n") if meta.get("poc_code") else None),
        confidence=(str(meta.get("confidence") or "candidate").strip().lower()),
        last_verified=(str(meta["last_verified"]).strip() if meta.get("last_verified") else None),
        source=lst("source"),
        license=(str(meta["license"]).strip() if meta.get("license") else None),
        body=body,
    )


def render_card(card: Card) -> str:
    return dump_frontmatter(card) + "\n" + card.body.lstrip("\n")


# ---------------- 校验 ----------------
def validate_card(card: Card, artifacts_root=None, poc_exists=None) -> List[str]:
    """返回问题列表；空列表表示通过（§8.3 质量门槛 + §4.4 体积）。"""
    import os
    from pathlib import Path

    issues: List[str] = []
    if not card.title:
        issues.append("title 为空")
    if not card.id:
        issues.append("id 为空")
    if card.confidence not in CONFIDENCE_LEVELS:
        issues.append(f"confidence 非法: {card.confidence}")
    if not card.license:
        issues.append("license 未记录")
    if not card.cve and not card.poc_path and not card.poc_code:
        issues.append("无 CVE 且无可执行 POC，不入库")

    fm = dump_frontmatter(card).encode("utf-8")
    body = card.body.encode("utf-8")
    text = render_card(card).encode("utf-8")
    if len(fm) > LIMIT_FRONTMATTER_BYTES:
        issues.append(f"frontmatter 超限 {len(fm)}B > {LIMIT_FRONTMATTER_BYTES}B")
    if len(body) > LIMIT_BODY_BYTES:
        issues.append(f"正文超限 {len(body)}B > {LIMIT_BODY_BYTES}B")
    if len(text) > LIMIT_CARD_BYTES:
        issues.append(f"单卡超限 {len(text)}B > {LIMIT_CARD_BYTES}B")
    if card.poc_code:
        pc = card.poc_code.encode("utf-8")
        if len(pc) > LIMIT_POC_CODE_BYTES or card.poc_code.count("\n") + 1 > LIMIT_POC_CODE_LINES:
            issues.append("poc_code 超限（<=1.5KB 且 <=40 行），必须转 artifacts/")

    secs = card.sections()
    for name in SECTIONS:
        if name not in secs or not secs[name]:
            issues.append(f"缺少段落: {name}")
            continue
        n = len(secs[name])
        if n > SECTION_LIMIT_CHARS[name]:
            issues.append(f"段落超预算: {name} {n} 字 > {SECTION_LIMIT_CHARS[name]}")

    if card.poc_path:
        ok = False
        target = None
        if artifacts_root is not None:
            # §11：禁止 `..`/symlink 逃逸
            try:
                from .paths import safe_join
                target = safe_join(Path(artifacts_root), card.poc_path)
            except ValueError as e:
                issues.append(f"artifact 路径不合法: {e}")
            else:
                # poc_path 是相对 kb 根的路径（如 artifacts/CVE-x/README.md）
                base = Path(artifacts_root)
                ok = target.exists() or (base / "kb" / card.poc_path).exists()
        if poc_exists is not None:
            ok = poc_exists(card.poc_path)
        elif artifacts_root is None:
            target = Path("kb") / card.poc_path
            ok = target.exists()
        if not ok:
            # 降级而非拒绝（§8.3）
            issues.append("poc_missing")
        elif target is not None and target.exists():
            # §4.4 / §8.3：单卡 artifacts <= 1MB
            if target.is_file() and target.stat().st_size > LIMIT_ARTIFACTS_BYTES:
                issues.append(f"单个 artifact 超限 {target.stat().st_size}B")
            elif target.is_file():
                total = sum(p.stat().st_size for p in target.parent.rglob("*") if p.is_file())
                if total > LIMIT_ARTIFACTS_BYTES:
                    issues.append(f"单卡 artifacts 超限 {total}B")
    return issues


_PLACEHOLDER = re.compile(r"\{\{[^}]*\}\}|\$\{[^}]*\}|\$[A-Z_]{3,}|<[^>]{1,30}>|xxxx|XXXX|example|EXAMPLE|changeme|your[_-]?password|your[_-]?token")


def _is_placeholder(value: str) -> bool:
    """判断疑似凭据是否只是模板占位符/示例值。"""
    v = value.strip().strip("'\"")
    if not v:
        return True
    if _PLACEHOLDER.search(v):
        return True
    # 模板变量形态：password={{password}}
    if v.startswith("{{") or v.startswith("$"):
        return True
    return False


def scan_secrets(text: str) -> List[str]:
    """token/key/flag 粗扫描（§11）。返回命中说明列表。

    对 password/passwd 这类弱特征，排除模板占位符（{{...}}/${...}/<...>）
    与常见示例值，避免把 POC 里的 `password={{password}}` 误判为泄漏。
    """
    hits: List[str] = []
    patterns = [
        (r"\bflag\{[^}]{4,}\}", "flag{...}"),
        (r"\bCTF\{[^}]{4,}\}", "CTF{...}"),
        (r"\bAKIA[0-9A-Z]{16}\b", "aws-access-key"),
        (r"\bghp_[A-Za-z0-9]{30,}\b", "github-token"),
        (r"\bsk-[A-Za-z0-9]{20,}\b", "openai-key"),
        (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private-key"),
        (r"(?i)\bbearer\s+[A-Za-z0-9_\-\.]{20,}", "bearer-token"),
    ]
    for pat, label in patterns:
        for m in re.finditer(pat, text):
            if not _is_placeholder(m.group(0)):
                hits.append(label)
                break

    # 弱特征单独判断：只保留"看起来像真实凭据"的值
    for m in re.finditer(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*(['\"]?)([^\s'\"&]{6,})\1", text):
        val = m.group(2)
        if _is_placeholder(val):
            continue
        # 纯字母数字且长度 >=6 才认作真实口令；含 = & {{ }} 等一律忽略
        if re.fullmatch(r"[A-Za-z0-9!@#$%^*()_+\-]{6,}", val):
            hits.append("inline-password")
            break
    return hits
