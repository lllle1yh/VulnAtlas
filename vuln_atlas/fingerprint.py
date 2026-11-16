"""指纹派生（§4.2 / §6.1）。

卡片的 `fingerprint` 只放"能从响应头/路径/产品名识别组件"的短 token。
数据来源：
  1) 解析器已经抽到的指纹（curated 卡、nuclei matcher/path）；
  2) 本模块的 data/fingerprints.json 产品映射；
  3) 产品/厂商名的保守兜底（仅当长度足够且不是泛词）。

不做网络请求、不调用 LLM，保持离线与确定性。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, List, Optional

from . import paths

# 这些 token 对识别产品没有区分度，rank.py 也会过滤
GENERIC = {
    "server", "via", "etag", "x-cache", "set-cookie", "content-type", "host",
    "cookie", "user-agent", "date", "connection", "keep-alive", "http", "https",
    "web", "html", "text", "application", "utf-8", "chunked", "close",
}

_SUFFIXES = (
    "_server", "_dc", "_apps", "_collaboration_suite", "_xi", "_os", "_linux",
    "_kernel", "_firmware", "_plugin", "_module",
)

_MAP: Optional[dict] = None


def _load_map() -> dict:
    global _MAP
    if _MAP is not None:
        return _MAP
    path = paths.repo_root() / "data" / "fingerprints.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        _MAP = {str(k).lower(): [str(x) for x in v] for k, v in raw.items() if isinstance(v, list)}
    except (OSError, json.JSONDecodeError, AttributeError):
        _MAP = {}
    return _MAP


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", str(s or "").strip().lower().replace("_", " "))


def _keys(product: str, vendor: str) -> Iterable[str]:
    p = _norm(product)
    if p:
        yield p
        for suf in _SUFFIXES:
            if p.endswith(suf.replace("_", " ")):
                yield p[: -len(suf.replace("_", " "))].strip()
        # 去掉末尾版本号：windows 10 -> windows
        yield re.sub(r"\s+\d+(?:\.\d+)*$", "", p).strip()
    v = _norm(vendor)
    if v and not p:
        yield v


def _clean(items: Iterable[str], limit: int = 6) -> List[str]:
    out: List[str] = []
    seen = set()
    for raw in items:
        s = re.sub(r"\s+", " ", str(raw or "").strip().lower())
        if not s or s in seen:
            continue
        if s in GENERIC:
            continue
        if len(s) < 3:
            continue
        # 纯数字/纯符号对识别没有意义
        if re.fullmatch(r"[\d.\-_/]+", s):
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= limit:
            break
    return out


def derive_fingerprints(product: Optional[str], vendor: Optional[str],
                        existing: Optional[Iterable[str]] = None,
                        limit: int = 6) -> List[str]:
    """返回去重后的指纹列表，最多 limit 条。existing 优先。"""
    items: List[str] = list(existing or [])
    m = _load_map()
    for key in _keys(str(product or ""), str(vendor or "")):
        vals = m.get(key)
        if vals:
            items.extend(vals)
    # 产品名本身作为兜底：至少让 /product/version 查询有指纹可对
    p = _norm(str(product or ""))
    if p and p not in GENERIC and len(p) >= 4:
        items.append(p)
        items.append(re.sub(r"\s+\d+(?:\.\d+)*$", "", p))
    v = _norm(str(vendor or ""))
    if v and v not in GENERIC and len(v) >= 4 and v not in ("microsoft", "apple", "google", "linux"):
        items.append(f"{v} {p}".strip())
    return _clean(items, limit=limit)