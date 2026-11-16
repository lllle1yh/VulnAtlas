"""ingest 公共工具：快照登记、sha256、manifest 读写、CardDraft。"""
from __future__ import annotations

import hashlib
import json
import re
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..card import Card, SECTIONS


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


@dataclass
class CardDraft:
    """解析器输出（§8.2）。"""
    cve: Optional[str] = None
    title: str = ""
    aliases: List[str] = field(default_factory=list)
    vendor: Optional[str] = None
    product: Optional[str] = None
    versions: List[str] = field(default_factory=list)
    fingerprint: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    attack_surface: List[str] = field(default_factory=list)
    poc: List[Dict[str, str]] = field(default_factory=list)
    confidence: str = "candidate"
    source: List[str] = field(default_factory=list)
    description: str = ""
    marker: str = ""
    steps: str = ""
    poc_code: str = ""
    artifact_dir: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Manifest:
    """kb/manifest.json 读写。结构：{"generated_at":..., "snapshots":[...], "sources": {...}}"""

    def __init__(self, path: Path):
        self.path = path
        self.data: Dict[str, Any] = {"generated_at": None, "snapshots": [], "sources": {}}
        if path.exists():
            try:
                self.data = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        self.data.setdefault("snapshots", [])
        self.data.setdefault("sources", {})

    def add_snapshot(self, source: str, url: str, file: Optional[Path],
                     license: str = "", redistribute: bool = True,
                     status: str = "ok", note: str = "", bytes_: Optional[int] = None) -> Dict[str, Any]:
        rec: Dict[str, Any] = {
            "source": source,
            "url": url,
            "fetched_at": now_iso(),
            "sha256": sha256_file(file) if file and file.exists() else None,
            "bytes": bytes_ if bytes_ is not None else (file.stat().st_size if file and file.exists() else None),
            "license": license,
            "redistribute": redistribute,
            "status": status,
            "note": note,
        }
        # 同一 source 只保留最新一条
        self.data["snapshots"] = [s for s in self.data["snapshots"] if s.get("source") != source]
        self.data["snapshots"].append(rec)
        self.data["sources"][source] = {
            "status": status, "license": license, "redistribute": redistribute,
            "fetched_at": rec["fetched_at"], "note": note,
        }
        return rec

    def set_source_status(self, source: str, status: str, note: str = "",
                          license: str = "", redistribute: Optional[bool] = None) -> None:
        cur = self.data["sources"].get(source, {})
        cur.update({"status": status, "note": note})
        if license:
            cur["license"] = license
        if redistribute is not None:
            cur["redistribute"] = redistribute
        cur.setdefault("fetched_at", None)
        self.data["sources"][source] = cur

    def save(self) -> None:
        self.data["generated_at"] = now_iso()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def draft_to_card(d: CardDraft, body_budget: int = 5000) -> Card:
    """把 CardDraft 渲染成六段正文的 Card。"""
    d.title = clean_text(d.title)
    d.description = clean_text(d.description)
    d.steps = clean_text(d.steps)
    d.marker = clean_text(d.marker)
    d.aliases = [clean_text(a) for a in d.aliases if clean_text(a)]
    d.fingerprint = [clean_text(f) for f in d.fingerprint if clean_text(f)]
    d.versions = [clean_text(v) for v in d.versions if clean_text(v)]
    d.tags = [clean_text(t).lower() for t in d.tags if clean_text(t)]
    ident = d.description.strip() or d.title
    versions = "、".join(d.versions) if d.versions else "未标注"
    fps = "、".join(d.fingerprint) if d.fingerprint else "未标注"

    comp = d.product or d.vendor or ""
    head = f"{comp} 版本 {versions}" if comp else f"版本 {versions}"
    target = f"{head}；指纹：{fps}。{ident}" if fps != "未标注" else f"{head}。{ident}"
    surf = "、".join(d.attack_surface) or "http"
    pre = "需能访问到受影响组件的 " + surf + " 攻击面" + ("；无需认证。" if not d.fingerprint else "。")
    steps = d.steps.strip() or "（待补充最小复现步骤）"
    marker = d.marker.strip() or "（待补充预期 marker）"
    poc_path = next((p.get("path") for p in d.poc if p.get("path")), None)
    poc_code = (d.poc_code or next((p.get("code") for p in d.poc if p.get("code")), "")).strip() or None
    # §4.2：poc_path 必须是 kb 内相对路径（artifacts/...），不能指向 raw/ 内部
    if poc_path:
        poc_path = normalize_poc_path(poc_path, d.cve or _slug(d))
    evidence = f"本地证据：{poc_path}" if poc_path else "本地证据：无（仅元数据卡，未落 artifact）"
    fails = "未验证环境不适用；版本高于受影响范围时不适用。"

    card = Card(
        id=d.cve or _slug(d),
        cve=d.cve,
        title=d.title,
        aliases=d.aliases,
        vendor=d.vendor,
        product=d.product,
        versions=d.versions,
        fingerprint=d.fingerprint,
        tags=d.tags,
        attack_surface=d.attack_surface,
        poc_type=next((p.get("type") for p in d.poc if p.get("type")), None),
        poc_path=poc_path,
        poc_code=poc_code,
        confidence=d.confidence,
        last_verified=None,
        source=d.source,
        license="see-manifest",
    )
    # §4.0：仅 `最小步骤` 允许出现 URL（那是攻击目标/XML 命名空间）；
    # 其余段落的 URL 是参考文献，必须清除。
    card.set_sections({
        SECTIONS[0]: _clip(strip_external_urls(target), 220),
        SECTIONS[1]: _clip(strip_external_urls(pre), 200),
        SECTIONS[2]: _clip(steps, 600),
        SECTIONS[3]: _clip(strip_external_urls(marker), 200),
        SECTIONS[4]: _clip(strip_external_urls(evidence), 150),
        SECTIONS[5]: _clip(strip_external_urls(fails), 300),
    })
    return card


_CTRL = {i: None for i in list(range(0, 9)) + list(range(11, 32)) + [127]}


# §4.0：卡片正文不得出现需要联网才能打开的链接。
# 但 XML/SOAP namespace、OOB 域名、目标占位符是 POC 的必要组成部分，必须保留。
_URL_RE = re.compile(r"https?://[^\s)\\\]>\"'`，。；）]+", re.I)
# 只保留「明显不是参考资料」的 URL：XML/SOAP 命名空间、OOB 域名、目标占位符。
# 其它一律视为参考资料，按 §4.0 清除。
_URL_KEEP_HOSTS = (
    "schemas.xmlsoap.org", "www.w3.org", "tempuri.org", "www.opengis.net",
    "docs.oasis-open.org", "xmlsoap.org", "schemas.microsoft.com",
    "schemas.datacontract.org", "schemas.dmtf.org",
    "interact.sh", "oast.pro", "oast.me", "oast.fun", "oast.live",
    "oast.site", "oast.online", "dnslog.cn", "ceye.io",
    "localhost", "127.0.0.1", "0.0.0.0",
)


def is_external_reference(url: str) -> bool:
    """判断 URL 是否为「读者需要联网打开」的参考资料。

    False = 它属于 POC 组成部分（XML/SOAP namespace、OOB 域名、目标占位符、
            无点号主机名如 thin-vnc），必须保留。
    True  = 参考资料（github 文档页、厂商 guide、snyk 等），按 §4.0 清除。
    """
    if not url:
        return False
    u = url
    low = u.lower()
    if any(k in u for k in ("TARGET", "TARG", "{{", "}}", "HOST", "Hostname",
                            "IP_ADDRESS", "MYDEVICEIP", "BaseURL", "<device",
                            "<Server", "<CACTI", "UserName:", "example.")):
        return False
    if any(h in low for h in _URL_KEEP_HOSTS):
        return False
    # 被截断的残片（…/...）：无法判断来源，按 POC 片段保留
    if "…" in u or u.rstrip().endswith("...") or "[" in u:
        return False
    host = re.sub(r"^https?://([^/:?#]+).*", r"\1", low)
    # 无点号主机名（thin-vnc / ip / a）/ 纯 IP：本地或内网占位目标
    if "." not in host:
        return False
    if re.fullmatch(r"[\d.]+", host):
        return False
    return True


def strip_external_urls(text: str) -> str:
    """把"需要联网才能打开"的链接替换为 [ref]，保留 namespace/OOB/占位符。"""
    if not text or "://" not in text:
        return text

    def repl(m: "re.Match") -> str:
        return "[ref]" if is_external_reference(m.group(0)) else m.group(0)

    return _URL_RE.sub(repl, text)


def clean_text(s: str) -> str:
    """去掉控制字符（保留 \n \t），避免 matcher 的二进制内容污染卡片。"""
    if not s:
        return ""
    s = str(s).translate(_CTRL)
    s = s.replace("\x00", "")
    # 注意：这里不做 URL 清洗。是否保留 URL 取决于它出现在哪一段：
    # `最小步骤` 里的 URL 是攻击目标/命名空间（必须保留），
    # 其它段落里的 URL 是参考资料（按 §4.0 必须清除）。见 draft_to_card()。
    return s


def normalize_poc_path(path: str, cve: str) -> str:
    """把各源的内部路径统一成 artifacts/<CVE>/<file> 形态。

    nuclei: http/cves/2020/CVE-2020-16846.yaml -> artifacts/CVE-2020-16846/nuclei-CVE-2020-16846.yaml
    edb:    exploits/windows/local/21344.txt -> artifacts/<CVE>/edb-21344.txt
    """
    import os
    p = str(path).replace("\\", "/").strip()
    if p.startswith("artifacts/"):
        return p
    base = os.path.basename(p) or "poc.txt"
    tag = "nuclei-" if "/cves/" in p or p.endswith(".yaml") else ("edb-" if p.startswith("exploits/") else "")
    return f"artifacts/{cve}/{tag}{base}"


def _clip(s: str, n: int) -> str:
    s = s.strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _slug(d: CardDraft) -> str:
    base = f"{d.product or d.vendor or 'unknown'}-{d.title}"
    return "wiki-" + hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]
