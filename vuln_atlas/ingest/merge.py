"""合并规则（§5）：一个 CVE 一张卡。

优先级：
  1. NVD 提供主体（title / 描述 / 版本 / tags）
  2. KEV / EPSS 只做 enrich
  3. ExploitDB / Nuclei / Metasploit 提供 POC 指针
  4. 本仓库已有 verified 卡优先覆盖 steps/marker/confidence
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from ..card import Card, SECTIONS
from ..fingerprint import derive_fingerprints
from .common import CardDraft, draft_to_card

# 可执行性优先（§5）：有完整可复制命令的排最前
POC_PRIORITY = {"curl": 9, "python": 9, "http": 8, "nuclei": 7, "msf": 3, "exploit-db": 2, "github-poc": 1}
CONF_RANK = {"verified": 3, "candidate": 2, "unverified": 1}


@dataclass
class Merged:
    cve: str
    drafts: List[CardDraft] = field(default_factory=list)
    kev: Optional[Dict[str, object]] = None
    epss: Optional[Dict[str, object]] = None


def pick_base(drafts: List[CardDraft]) -> CardDraft:
    """选一个基底：优先 NVD（有描述），其次信息最多的。"""
    def score(d: CardDraft) -> Tuple[int, int]:
        return (
            3 if "nvd" in d.source else (2 if d.description else 1),
            len(d.versions) + len(d.tags) + (2 if d.product else 0) + (2 if d.description else 0),
        )
    return max(drafts, key=score)


def merge_drafts(drafts: Iterable[CardDraft],
                 kev: Optional[Dict[str, Dict[str, object]]] = None,
                 epss: Optional[Dict[str, Dict[str, object]]] = None,
                 max_per_cve: int = 4) -> List[Card]:
    groups: Dict[str, Merged] = {}
    for d in drafts:
        if not d.cve:
            continue
        g = groups.setdefault(d.cve.upper(), Merged(cve=d.cve.upper()))
        g.drafts.append(d)

    out: List[Card] = []
    for cve, g in groups.items():
        base = pick_base(g.drafts)

        # 1) 字段合并：base 缺失字段从其它 draft 补
        def first(attr, default=None):
            if getattr(base, attr):
                return getattr(base, attr)
            for d in g.drafts:
                v = getattr(d, attr)
                if v:
                    return v
            return default

        tags = sorted({t for d in g.drafts for t in d.tags})
        surfaces = sorted({s for d in g.drafts for s in d.attack_surface}) or ["http"]
        versions = list(dict.fromkeys(v for d in g.drafts for v in d.versions))[:4]
        fps = list(dict.fromkeys(f for d in g.drafts for f in d.fingerprint))[:6]
        product = first("product")
        vendor = first("vendor")
        # §4.2：自动卡也要有可用于识别的 fingerprint；已有指纹优先，产品映射补齐。
        fps = derive_fingerprints(product, vendor, fps)
        sources = sorted({s for d in g.drafts for s in d.source})
        # alias 兜底过滤：仓库名（含 /）、纯数字 id、过短的串都不作为检索 alias，
        # 它们对识别漏洞没有帮助，只会污染 FTS 的 aliases 列。
        def _alias_ok(a: str) -> bool:
            a = str(a).strip()
            if len(a) < 3:
                return False
            if "/" in a:                       # owner/repo
                return False
            if a.isdigit():                    # EDB id / BID
                return False
            return True

        aliases = list(dict.fromkeys(
            a for d in g.drafts for a in d.aliases if _alias_ok(str(a))
        ))[:6]

        # 2) POC 选择（§5：verified > candidate > unverified；可执行性优先）
        #    Metasploit 用 poc_code（module 路径 + use/set/run），GitHub-PoC 只有
        #    存在性元数据；两者都没有本地源码，因此不能被当成可执行 POC 计分。
        pocs = [p for d in g.drafts for p in d.poc if p.get("path") or p.get("code")]
        pocs.sort(key=lambda p: (-POC_PRIORITY.get(str(p.get("type")), 0)))
        best_poc = pocs[0] if pocs else None
        poc_code = (best_poc or {}).get("code") or ""

        conf = max((d.confidence for d in g.drafts), key=lambda c: CONF_RANK.get(c, 0))
        # 只有 GitHub-PoC 元数据、没有本地 POC/可执行代码 → unverified（§4.2）
        if conf == "candidate" and not poc_code and not (best_poc or {}).get("path") \
                and "github-poc" in sources:
            conf = "unverified"

        # 3) enrich
        k = (kev or {}).get(cve)
        e = (epss or {}).get(cve)
        extra_bits = []
        if k:
            extra_bits.append("KEV 已知被利用")
            if not same_product(k.get("product"), base.product):
                tags = sorted(set(tags))
        if e:
            extra_bits.append(f"EPSS {e['epss']:.3f}")

        body_desc = first("description") or base.title
        if extra_bits:
            body_desc = f"{body_desc}（{'; '.join(extra_bits)}）"

        # steps/marker 必须和选中的 POC 同源，否则会出现
        # "poc_type=msf 但 steps 写 GitHub 元数据" 这种自相矛盾的卡。
        def _poc_key(p: dict) -> tuple:
            return (str(p.get("type") or ""), str(p.get("path") or ""), str(p.get("code") or ""))

        def _rank_text(v: object) -> tuple:
            s = str(v)
            if "待补充" in s:
                return (0, len(s))
            if "GitHub PoC" in s:
                return (1, len(s))
            if "将 EDB PoC" in s or "按 EDB" in s or "EDB-" in s:
                return (1.5, len(s))
            return (2, len(s))

        def best_text_from(drafts: List[CardDraft], attr: str, default: str = "") -> str:
            vals = [getattr(d, attr) for d in drafts if getattr(d, attr)]
            return max(vals, key=_rank_text) if vals else default

        def best_text(attr: str) -> str:
            return best_text_from(g.drafts, attr, "")

        src_drafts = []
        if best_poc is not None:
            key = _poc_key(best_poc)
            src_drafts = [d for d in g.drafts if any(_poc_key(p) == key for p in d.poc)]
        if src_drafts:
            steps = best_text_from(src_drafts, "steps", "（待补充最小复现步骤）")
            marker = best_text_from(src_drafts, "marker", "（待补充预期 marker）")
        else:
            steps = best_text("steps")
            marker = best_text("marker")

        d2 = CardDraft(
            cve=cve,
            title=(base.title or cve)[:160],
            aliases=aliases,
            vendor=vendor,
            product=product,
            versions=versions,
            fingerprint=fps,
            tags=tags,
            attack_surface=surfaces,
            poc=[best_poc] if best_poc else [],
            confidence=conf,
            source=sources,
            description=str(body_desc)[:600],
            steps=steps,
            marker=marker,
            poc_code=poc_code,
        )
        card = draft_to_card(d2)
        if not card.title:
            card.title = cve
        out.append(card)
    return out


def same_product(a, b) -> bool:
    if not a or not b:
        return False
    return str(a).lower().replace(" ", "").replace("-", "") == str(b).lower().replace(" ", "").replace("-", "")


def merge_with_existing(new_cards: List[Card], existing: List[Card]) -> List[Card]:
    """本仓库已验证卡优先：同 cve 时用 existing 覆盖 steps/marker/confidence/poc。"""
    by_key = {(c.cve or c.id).upper(): c for c in existing}
    merged: Dict[str, Card] = {}
    for c in new_cards:
        merged[(c.cve or c.id).upper()] = c
    for key, ex in by_key.items():
        cur = merged.get(key)
        if cur is None:
            merged[key] = ex
            continue
        if CONF_RANK.get(ex.confidence, 0) >= CONF_RANK.get(cur.confidence, 0):
            secs_cur = cur.sections()
            secs_ex = ex.sections()
            for name in SECTIONS:
                if secs_ex.get(name):
                    secs_cur[name] = secs_ex[name]
            cur.set_sections(secs_cur)
            cur.confidence = ex.confidence
            cur.last_verified = ex.last_verified
            if ex.poc_path or ex.poc_code:
                cur.poc_path = ex.poc_path
                cur.poc_code = ex.poc_code
                cur.poc_type = ex.poc_type
            cur.source = sorted(set(cur.source + ex.source))
    return list(merged.values())
