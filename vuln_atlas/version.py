"""版本表达与过滤（§6.2 版本过滤在 Python 做）。"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

OPS = ("<=", ">=", "==", "=", "!=", "<", ">")
_SEP = re.compile(r"\s*(?:,|;|&&|\band\b)\s*", re.I)


def _parse_one(s: str) -> Tuple[str, str]:
    s = s.strip()
    for op in OPS:
        if s.startswith(op):
            return ("==" if op == "=" else op), s[len(op):].strip()
    return "~", s  # 无操作符 => 视为区间/前缀


def _key(v: str):
    """把版本切成可比较元组。数字段按数值比，字母段按字典序，保证不抛异常。"""
    v = v.strip().lower().lstrip("v")
    parts = re.findall(r"\d+|[a-z]+", v)
    key = []
    for p in parts:
        if p.isdigit():
            key.append((0, int(p), ""))
        else:
            key.append((1, 0, p))
    while key and key[-1][0] == 0 and key[-1][1] == 0:
        key.pop()
    return tuple(key) if key else ((0, 0, ""),)


def _cmp(a: str, b: str) -> int:
    ka, kb = _key(a), _key(b)
    n = max(len(ka), len(kb))
    ka = ka + ((0, 0, ""),) * (n - len(ka))
    kb = kb + ((0, 0, ""),) * (n - len(kb))
    return (ka > kb) - (ka < kb)


def matches(version: str, expression: str) -> bool:
    """判断 version 是否满足 expression，例如 '<= 3.7.1' / '>= 2.0,< 2.4' / '3.7.x'。"""
    if not version or not expression:
        return False
    expr = expression.strip()
    if expr in ("*", "any", "all"):
        return True
    for part in _SEP.split(expr):
        if not part:
            continue
        op, target = _parse_one(part)
        if not target:
            continue
        if op == "~":
            # 区间式 "2.0 - 2.4"
            if " - " in target:
                lo, hi = [x.strip() for x in target.split(" - ", 1)]
                if _cmp(version, lo) < 0 or _cmp(version, hi) > 0:
                    return False
                continue
            if "*" in target or "x" in target.lower():
                prefix = re.split(r"[*xX]", target)[0].rstrip(".")
                if not (version.lower().lstrip("v") == prefix or version.startswith(prefix + ".")):
                    return False
                continue
            # 无操作符等价于前缀匹配（含精确匹配）
            t = target.lower().lstrip("v")
            v = version.lower().lstrip("v")
            if not (v == t or v.startswith(t + ".")):
                return False
            continue
        c = _cmp(version, target)
        ok = {
            "<=": c <= 0, ">=": c >= 0, "==": c == 0, "!=": c != 0, "<": c < 0, ">": c > 0,
        }[op]
        if not ok:
            return False
    return True


def any_match(version: Optional[str], expressions: List[str]) -> Optional[bool]:
    """None 表示无法判断（无版本或无表达式）。"""
    if not version or not expressions:
        return None
    return any(matches(version, e) for e in expressions)
