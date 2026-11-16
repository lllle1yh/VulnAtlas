"""请求归一化 + 查询路由（§6.1 / §6.1.1）。

不做 embedding：把 agent 传来的 HTTP/curl/nmap/错误原文抽成结构化字段。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlsplit

CVE_RE = re.compile(r"\bCVE[-_ /]?(\d{4})[-_ /]?(\d{4,7})\b", re.I)
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
VERSION_RE = re.compile(r"\b\d+(?:\.\d+){1,3}(?:[-_][A-Za-z0-9.]+)?\b")
_STATUS_RE = re.compile(r"\bHTTP/\d(?:\.\d)?\s+(\d{3})")
_NMAP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b", re.M)
_NMAP_SVC = re.compile(r"^(\d{1,5})/tcp\s+open\s+(\S+)(?:\s+(.*))?$", re.M)
_HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9\-]{1,40}):\s*(.+)$", re.M)

# 常见指纹头，命中就当作 fingerprint 信号
FINGERPRINT_HEADERS = {
    "server", "x-powered-by", "x-runtime", "x-aspnet-version", "x-generator",
    "x-drupal-cache", "x-litespeed-cache", "via", "x-cache", "set-cookie",
}

# 攻击面关键字（中英）
SURFACE_WORDS = {
    "http": ["http", "https", "web", "url", "接口", "网站", "网页"],
    "lfi": ["lfi", "本地文件包含", "文件包含", "file inclusion", "path traversal", "路径穿越", "目录穿越", "任意文件读取", "任意文件下载"],
    "rce": ["rce", "远程代码执行", "命令执行", "代码执行", "command injection", "命令注入", "反序列化", "deserialization"],
    "sqli": ["sql", "注入", "sqli", "injection"],
    "upload": ["上传", "upload", "文件上传"],
    "ssrf": ["ssrf", "服务端请求伪造"],
    "xss": ["xss", "跨站"],
    "auth": ["认证绕过", "越权", "auth bypass", "unauthorized", "未授权", "默认口令", "弱口令"],
    "ad": ["域", "ad", "active directory", "kerberos", "smb", "ldap"],
}

PRODUCT_HINTS = [
    ("sprockets", ["sprockets"]), ("ruby on rails", ["rails", "ruby on rails", "rubyonrails"]),
    ("log4j", ["log4j", "log4shell"]), ("spring", ["spring", "springboot", "spring boot"]),
    ("struts2", ["struts", "struts2", "s2-"]), ("fastjson", ["fastjson"]),
    ("weblogic", ["weblogic"]), ("tomcat", ["tomcat"]), ("jenkins", ["jenkins"]),
    ("gitlab", ["gitlab"]), ("confluence", ["confluence"]), ("drupal", ["drupal"]),
    ("thinkphp", ["thinkphp"]), ("shiro", ["shiro"]), ("nginx", ["nginx"]),
    ("httpd", ["apache httpd", "httpd", "apache/"]), ("elasticsearch", ["elasticsearch"]),
    ("openssh", ["openssh", "ssh"]), ("vsftpd", ["vsftpd"]), ("redis", ["redis"]),
    ("mysql", ["mysql"]), ("wordpress", ["wordpress"]), ("jira", ["jira"]),
    ("exchange", ["exchange"]), ("citrix", ["citrix", "netscaler"]),
    ("ivanti", ["ivanti"]), ("fortinet", ["fortinet", "fortios"]), ("citrix-adc", ["adc"]),
    ("jmeter", ["jmeter"]), ("phpmyadmin", ["phpmyadmin"]), ("zabbix", ["zabbix"]),
]


@dataclass
class Query:
    cve: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    attack_surface: List[str] = field(default_factory=list)
    fingerprint: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    raw: str = ""
    free_text: str = ""
    product_explicit: bool = False

    def is_structured(self) -> bool:
        return bool(self.cve or (self.product and self.version) or self.attack_surface or self.fingerprint)


def normalize_cve(s: str) -> Optional[str]:
    m = CVE_RE.search(s or "")
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else None


def _version_from_url(u: str) -> Optional[str]:
    try:
        parts = urlsplit(u)
    except ValueError:
        return None
    for m in VERSION_RE.finditer(parts.path + " " + parts.query):
        v = m.group(0)
        # 排除 IP、日期、端口形态
        if v.count(".") >= 1 and not re.fullmatch(r"\d{4}\.\d{1,2}\.\d{1,2}", v):
            return v
    return None


def _products_in(text: str) -> List[str]:
    low = text.lower()
    hits = []
    for canon, keys in PRODUCT_HINTS:
        for k in keys:
            if k in low:
                hits.append(canon)
                break
    return hits


def _surfaces_in(text: str) -> List[str]:
    low = text.lower()
    return [tag for tag, words in SURFACE_WORDS.items() if any(w in low for w in words)]


def parse_request(request: str) -> Dict[str, object]:
    """把 HTTP / curl / nmap / 泛文本抽成字典。"""
    out: Dict[str, object] = {
        "method": None, "path": None, "headers": {}, "body": None,
        "status": None, "url": None, "host": None, "port": None,
        "service": None, "product": None, "version": None,
        "cve": None, "fingerprint": [], "attack_surface": [],
    }
    if not request:
        return out
    text = request

    m = _STATUS_RE.search(text)
    if m:
        out["status"] = int(m.group(1))

    um = URL_RE.search(text)
    if um:
        url = um.group(0).rstrip(".,);")
        out["url"] = url
        try:
            u = urlsplit(url)
            out["host"] = u.hostname
            out["port"] = u.port
            out["path"] = u.path or "/"
            if u.query:
                out["path"] += "?" + u.query
            out["method"] = "GET"
        except ValueError:
            pass

    method_m = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)", text)
    if method_m:
        out["method"] = method_m.group(1)
        out["path"] = method_m.group(2)
        if out["path"].startswith("/"):
            hm = re.search(r"^Host:\s*(\S+)", text, re.M | re.I)
            if hm:
                out["host"] = hm.group(1)

    for hm in _HEADER_RE.finditer(text):
        k, v = hm.group(1), hm.group(2).strip()
        if k.lower() in FINGERPRINT_HEADERS or k.lower() in ("host", "cookie", "user-agent", "content-type"):
            out["headers"][k.lower()] = v

    nm = _NMAP_RE.search(text)
    if nm:
        out["host"] = out["host"] or nm.group(1)
        out["port"] = out["port"] or int(nm.group(2))
    services = []
    for sm in _NMAP_SVC.finditer(text):
        banner = (sm.group(3) or "").strip()
        ver = None
        if banner:
            vm = VERSION_RE.search(banner)
            if vm:
                ver = vm.group(0)
        services.append({
            "port": int(sm.group(1)),
            "service": sm.group(2),
            "banner": banner,
            "version": ver,
            "product": banner.split()[0].lower() if banner.split() else None,
        })
    if services:
        # 优先 http/https，其次第一个有版本号的
        web = [s for s in services if s["service"] in ("http", "https", "http-proxy", "ssl/http")]
        withver = [s for s in services if s["version"]]
        pick = (web or withver or services)[0]
        out["port"] = out["port"] or pick["port"]
        out["service"] = pick["service"]
        out["version"] = out["version"] or pick["version"]
        out["product"] = out["product"] or pick["product"]

    out["cve"] = normalize_cve(text)

    if not out["version"]:
        cand = out["url"] or out["path"]
        if cand:
            out["version"] = _version_from_url(str(cand))

    prods = _products_in(text)
    if not out["product"] and prods:
        out["product"] = prods[0]

    fps: List[str] = []
    for k, v in out["headers"].items():
        if k in FINGERPRINT_HEADERS:
            # 头名本身常是产品指纹（X-Runtime / X-Powered-By / ETag）
            fps.append(k)
            fps.append(v if len(v) < 80 else v[:80])
    for m2 in re.finditer(r"ETag:\s*(W/)?\"?([^\r\n\"]{1,40})", text):
        fps.append("ETag")
    out["fingerprint"] = list(dict.fromkeys(fps))
    out["attack_surface"] = _surfaces_in(text)
    return out


def build_query(
    query: str = "",
    request: Optional[str] = None,
    product: Optional[str] = None,
    version: Optional[str] = None,
    cve: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> Query:
    """合并显式参数与原文抽取结果；显式参数优先。"""
    raw_parts = [p for p in (query or "", request or "") if p]
    raw = "\n".join(raw_parts)
    parsed = parse_request(raw) if raw else {}

    q = Query(raw=raw)
    q.cve = normalize_cve(cve or "") or (parsed.get("cve") or None)
    explicit_product = (product or "").strip().lower()
    if explicit_product:
        q.product = _canon_product(explicit_product)
        q.product_explicit = True
    elif parsed.get("product"):
        q.product = _canon_product(str(parsed["product"]))
    q.version = (version or "").strip() or (parsed.get("version") or None)
    q.tags = [t.strip().lower() for t in (tags or []) if t and t.strip()]
    q.attack_surface = list(dict.fromkeys(q.tags + list(parsed.get("attack_surface") or []))) if (q.tags or parsed.get("attack_surface")) else []
    q.fingerprint = list(parsed.get("fingerprint") or [])
    # §6.1.1 示例里 request 归一化也会把路径片段当指纹信号（如 "/assets/file:"）
    pth = parsed.get("path")
    if isinstance(pth, str) and len(pth) >= 5:
        q.fingerprint.append(pth)
        for seg in re.findall(r"/[A-Za-z0-9_.\-]{2,}/", pth):
            q.fingerprint.append(seg)

    free = query or ""
    if request:
        free = (free + "\n" + request).strip()
    # 去掉 CVE 号，避免污染 FTS 词
    q.free_text = CVE_RE.sub(" ", free).strip()
    if not q.free_text and parsed.get("path"):
        q.free_text = str(parsed.get("path"))
    return q


def _canon_product(p: str) -> str:
    p = p.strip().lower().replace("_", " ")
    for canon, keys in PRODUCT_HINTS:
        if p == canon or p in keys:
            return canon
    return p


def extract_tags_from_text(text: str) -> List[str]:
    return _surfaces_in(text)
