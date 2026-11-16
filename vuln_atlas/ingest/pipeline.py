"""ingest 编排：snapshot -> normalize -> merge -> render -> index（§8.1）。

各源缺失时不影响其他源；缺失原因写入 manifest（§3.4）。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional

from .. import paths
from ..card import Card
from ..indexer import build_index, load_cards
from . import epss as epss_m
from . import exploitdb as edb_m
from . import kev as kev_m
from . import nvd as nvd_m
from .merge import merge_drafts, merge_with_existing
from .common import Manifest, CardDraft

# 全部 17 类数据源（§3.4），用于 manifest 完整性检查
ALL_SOURCES = [
    "nvd", "kev", "epss", "cwe", "exploitdb", "nuclei", "metasploit", "getsploit",
    "github-poc", "trickest", "vulhub", "hacktricks", "payloads", "internalallthethings",
    "xianzhi", "knowledges", "verified-cards",
]


def _raw(source: str, *parts: str) -> Path:
    return paths.raw_dir().joinpath(source, *parts)


def collect_drafts(limit_per_source: int = 0, min_epss: float = 0.1) -> (List[CardDraft], Dict[str, str]):
    """返回 (drafts, report)。report: source -> ok/partial/unavailable:reason。"""
    drafts: List[CardDraft] = []
    report: Dict[str, str] = {}

    def note(src: str, msg: str) -> None:
        report[src] = msg

    # NVD
    nvd_files = sorted(paths.raw_dir().glob("nvd/*.json.gz"))
    if nvd_files:
        n = 0
        for f in nvd_files:
            for d in nvd_m.parse(f, limit=limit_per_source or None):
                drafts.append(d)
                n += 1
        note("nvd", f"ok:{n}")
    else:
        note("nvd", "unavailable: kb/raw/nvd/ 下无 nvdcve-2.0-*.json.gz")

    # KEV / EPSS 只做 enrich，不产卡
    kev_idx = {}
    kev_path = _raw("kev", "known_exploited_vulnerabilities.json")
    note("kev", f"ok:{len(kev_idx)}" if kev_path.exists() else "unavailable: 需先 fetch kev")
    if kev_path.exists():
        kev_idx = kev_m.load_index(kev_path)
        note("kev", f"ok:{len(kev_idx)}")

    epss_idx = {}
    epss_path = _raw("epss", "epss_scores-current.csv.gz")
    if epss_path.exists():
        epss_idx = epss_m.load_index(epss_path, min_epss=min(min_epss, 0.01))
        note("epss", f"ok:{len(epss_idx)}")
    else:
        note("epss", "unavailable: 需先 fetch epss")

    # ExploitDB
    edb_path = _raw("exploitdb", "files_exploits.csv")
    if edb_path.exists():
        n = 0
        for d in edb_m.parse(edb_path, limit=limit_per_source):
            drafts.append(d)
            n += 1
        note("exploitdb", f"ok:{n}")
    else:
        note("exploitdb", "unavailable: 需先 fetch exploitdb_csv")

    # Nuclei / GitHub-PoC / Metasploit：目录级解析
    for src, mod_name in (("nuclei", "nuclei"), ("github-poc", "github_poc"),
                          ("metasploit", "msf"), ("vulhub", "vulhub"),
                          ("payloads", "payloads")):
        d0 = paths.raw_dir() / src
        if not d0.exists() or not any(d0.iterdir()):
            note(src, f"unavailable: kb/raw/{src}/ 为空，未做快照")
            continue
        try:
            mod = __import__(f"vuln_atlas.ingest.{mod_name}", fromlist=["parse_tree"])
            limit = limit_per_source or 0
            n = 0
            for d in mod.parse_tree(d0, limit=limit):
                drafts.append(d)
                n += 1
            note(src, f"ok:{n}")
        except Exception as e:  # noqa: BLE001
            note(src, f"partial:{type(e).__name__}:{e}")

    # 预标记不可用源（原因固定，避免"以后再说"）
    fixed_unavailable = {
        "cwe": "partial: 只做标签，不单独产卡（随 nvd weaknesses 使用）",
        "getsploit": "unavailable: 依赖 Vulners 商业离线 DB，未取得授权",
        "trickest": "unavailable: kb/raw/trickest/ 为空，未做快照",
        "hacktricks": "unavailable: CC BY-NC 受限，需人工确认再分发范围",
        "internalallthethings": "unavailable: 仓库已迁移且未声明 license，需复核",
        "xianzhi": "unavailable: 无稳定公开 API，只能授权导出",
        "knowledges": "unavailable-local: kb/raw/knowledges/ 为空（原路径 C:\\Users\\30209\\...\\knowledges 本机不存在）",
        "verified-cards": "unavailable: 需实验侧导出 verified 卡",
    }
    for src, msg in fixed_unavailable.items():
        report.setdefault(src, msg)

    return drafts, report


STUB_MARKERS = ("待补充", "GitHub PoC", "将 EDB PoC", "EDB-")


def has_actionable_steps(card: Card) -> bool:
    """§5：真正可执行的步骤；GitHub 元数据/ExploitDB 骨架不算。"""
    s = (card.section("最小步骤") or "").strip()
    return bool(s) and not any(m in s for m in STUB_MARKERS)


def apply_retention_policy(cards: List[Card], kev_idx: Dict, epss_idx: Dict,
                           min_epss: float = 0.1, keep_years: int = 10,
                           promote_confidence: bool = True,
                           target_cards: int = 0) -> List[Card]:
    """§14 风险表：NVD 数据太大 -> 只保留近 10 年 + 有 POC/KEV/高 EPSS 的 CVE。

    保留下来的卡里，有真实 POC 的可提升到 candidate；KEV 卡标注来源。
    """
    from datetime import date
    cutoff_year = date.today().year - keep_years
    kept: List[Card] = []
    scored: List[tuple] = []

    for c in cards:
        key = (c.cve or c.id).upper()
        has_steps = has_actionable_steps(c)
        has_poc = bool(c.poc_path or c.poc_code or has_steps)
        has_gh_meta = "github-poc" in (c.source or [])
        # ExploitDB CSV 只提供 EDB 编号指针，没有本地源码；和 GitHub 元数据一样按弱证据保留。
        has_weak_meta = has_gh_meta or c.poc_type == "exploit-db"
        in_kev = key in kev_idx
        e = epss_idx.get(key)
        epss_val = float((e or {}).get("epss") or 0)
        high_epss = epss_val >= min_epss
        try:
            year = int(key.split("-")[1]) if key.upper().startswith("CVE-") else 9999
        except (ValueError, IndexError):
            year = 9999
        recent = year >= cutoff_year

        # GitHub 元数据卡是低置信覆盖，不作为"可执行 POC"参与排序，但允许入低置信库。
        if not (has_poc or in_kev or high_epss or has_weak_meta):
            continue
        if not recent and not in_kev:
            continue

        # 只有真实 POC/步骤才把 unverified 提升为 candidate；GitHub 元数据保持 unverified。
        if promote_confidence and (has_poc or in_kev) and c.confidence == "unverified":
            c.confidence = "candidate"
        if in_kev and "kev" not in c.source:
            c.source = sorted(set(c.source + ["kev"]))

        # 质量分：优先保留有可执行步骤 / KEV / 高 EPSS / 新近
        q = 0.0
        if has_steps:
            q += 40
        elif has_weak_meta:
            q += 5
        if c.poc_code:
            q += 20
        if c.poc_path:
            q += 10
        if in_kev:
            q += 30
        q += epss_val * 30
        q += max(0.0, (year - 2000)) * 0.15
        scored.append((q, year, key, c))

    if target_cards and len(scored) > target_cards:
        scored.sort(key=lambda x: (-x[0], -x[1], x[2]))
        kept = [x[3] for x in scored[:target_cards]]
    else:
        kept = [x[3] for x in scored]
    return kept


def run(limit_per_source: int = 0, write_cards: bool = True, max_cards: int = 0,
        min_epss: float = 0.1, keep_years: int = 10,
        cards_out: Optional[Path] = None,
        write_manifest: bool = True,
        target_cards: int = 0,
        materialize_artifacts: bool = True) -> Dict[str, object]:
    paths.ensure_dirs()
    drafts, report = collect_drafts(limit_per_source=limit_per_source, min_epss=min_epss)
    kev_path = _raw("kev", "known_exploited_vulnerabilities.json")
    epss_path = _raw("epss", "epss_scores-current.csv.gz")
    kev_idx = kev_m.load_index(kev_path) if kev_path.exists() else {}
    epss_idx = epss_m.load_index(epss_path, min_epss=min(min_epss, 0.01)) if epss_path.exists() else {}

    merged_all = merge_drafts(drafts, kev=kev_idx, epss=epss_idx)
    merged = apply_retention_policy(merged_all, kev_idx, epss_idx,
                                    min_epss=min_epss, keep_years=keep_years,
                                    target_cards=target_cards)
    if max_cards:
        merged = merged[:max_cards]

    existing = [c for _p, c in load_cards()]
    existing_by_cve = {(c.cve or c.id).upper(): c for c in existing}

    # 手工卡保护：由人工撰写/审阅过的卡（source 含 own-run 或 confidence=verified）
    # 绝不被自动生成的元数据卡覆盖，无论其 confidence 是什么。
    def is_curated(card: Card) -> bool:
        srcs = {str(s).lower() for s in (card.source or [])}
        return ("own-run" in srcs) or card.confidence == "verified"

    curated = {k for k, v in existing_by_cve.items() if is_curated(v)}

    to_write: List[Card] = []
    skipped_curated = 0
    for c in merged:
        key = (c.cve or c.id).upper()
        if key in curated:
            skipped_curated += 1
            continue
        to_write.append(c)

    written = 0
    out_dir = Path(cards_out) if cards_out else paths.cards_dir()
    artifacts_ok = 0
    rejected_publish: Dict[str, int] = {}

    # 发布前过滤：落盘的卡必须能通过 §8.3 质量门槛 + §11 密钥扫描，
    # 否则会出现「文件数 20000、可索引 19970」的不一致。
    # 被拒的槽位由后面质量分次高的候选补足，保证最终有效卡数达标。
    from ..card import render_card, validate_card, scan_secrets
    from . import artifacts as art_m

    def publishable(card: Card) -> bool:
        issues = validate_card(card, artifacts_root=paths.kb_root())
        blocking = [i for i in issues if i != "poc_missing"]
        if blocking:
            rejected_publish["validate:" + blocking[0]] = rejected_publish.get("validate:" + blocking[0], 0) + 1
            return False
        leaks = scan_secrets(render_card(card))
        if leaks:
            rejected_publish["secret:" + leaks[0]] = rejected_publish.get("secret:" + leaks[0], 0) + 1
            return False
        return True

    accepted = [c for c in to_write if publishable(c)]

    # 不足目标数时，从剩余候选（未进 to_write 的）按原顺序补足
    if target_cards and len(accepted) < target_cards:
        pool = [c for c in merged if (c.cve or c.id).upper() not in
                {(a.cve or a.id).upper() for a in accepted}
                and (c.cve or c.id).upper() not in curated]
        for c in pool:
            if len(accepted) >= target_cards:
                break
            if publishable(c):
                accepted.append(c)
                to_write.append(c)

    if write_cards:
        out_dir.mkdir(parents=True, exist_ok=True)
        for c in accepted:
            if materialize_artifacts:
                art_m.apply(c)
                if c.poc_path:
                    artifacts_ok += 1
            (out_dir / f"{c.id}.md").write_text(render_card(c), encoding="utf-8")
            written += 1

    total_bytes = sum(f.stat().st_size for f in out_dir.glob("*.md")) if out_dir.exists() else 0

    # 写到临时目录时不碰正式 index.db，只报告体积
    stats = build_index(cards_dir=out_dir) if (write_cards and cards_out is None) else {"cards": written, "bytes": total_bytes}

    m = Manifest(paths.manifest_path())
    for src in ALL_SOURCES:
        status_msg = report.get(src, "unavailable: 未接入")
        status, _, note = status_msg.partition(":")
        m.set_source_status(src, status or "unavailable", note)
    m.data["pipeline"] = {
        "drafts": len(drafts),
        "merged_cves_before_policy": len(merged_all),
        "merged_cves": len(merged),
        "retention_policy": {"min_epss": min_epss, "keep_years": keep_years,
                              "target_cards": target_cards},
        "cards_written": written,
        "artifacts_materialized": artifacts_ok,
        "rejected_before_publish": rejected_publish,
        "cards_preserved_curated": skipped_curated,
        "index": stats,
        "sources": report,
    }
    if write_manifest:
        m.save()
    return {"drafts": len(drafts), "merged_before_policy": len(merged_all),
            "merged": len(merged), "written": written,
            "artifacts": artifacts_ok, "rejected_before_publish": rejected_publish,
            "index": stats, "sources": report}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ingest-pipeline")
    ap.add_argument("--limit-per-source", type=int, default=2000,
                    help="每个源最多取多少条（0=不限）")
    ap.add_argument("--max-cards", type=int, default=0)
    ap.add_argument("--no-write", action="store_true",
                    help="只合并不落盘（也不改 manifest）")
    ap.add_argument("--min-epss", type=float, default=0.1)
    ap.add_argument("--keep-years", type=int, default=10)
    ap.add_argument("--cards-out", help="卡片输出目录（默认 kb/cards）")
    ap.add_argument("--target-cards", type=int, default=0,
                    help="目标卡数；超过时按质量分截断（0=不限）")
    ap.add_argument("--no-artifacts", action="store_true", help="不落 artifacts/")
    args = ap.parse_args(argv)
    print(json.dumps(run(limit_per_source=args.limit_per_source,
                         write_cards=not args.no_write,
                         max_cards=args.max_cards,
                         min_epss=args.min_epss,
                         keep_years=args.keep_years,
                         cards_out=Path(args.cards_out) if args.cards_out else None,
                         write_manifest=not args.no_write,
                         target_cards=args.target_cards,
                         materialize_artifacts=not args.no_artifacts),
                ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
