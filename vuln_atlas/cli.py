"""CLI（§7.1）：search / get / ingest / verify / stats / validate / check / repair / eval。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import db as dbm
from . import paths
from . import rank as rankm
from .card import card_from_text, render_card, validate_card, scan_secrets, SECTIONS
from .indexer import build_index, load_cards, check_card
from .router import build_query


def _print(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def cmd_search(args) -> int:
    q = build_query(
        query=args.query or "",
        request=args.request,
        product=args.product,
        version=args.version,
        cve=args.cve,
        tags=args.tags,
    )
    conn = dbm.connect(paths.db_path(), readonly=True)
    try:
        res = rankm.search(conn, q, top_k=args.top_k)
    finally:
        conn.close()
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(f"query: cve={q.cve} product={q.product} version={q.version} tags={q.tags}")
        if not res["results"]:
            print("(无结果)")
            print("suggested:", ", ".join(res.get("suggested_queries", [])[:6]))
        for i, r in enumerate(res["results"], 1):
            print(f"{i}. [{r['score']:>6}] {r['id']}  {r['title']}")
            print(f"     confidence={r['confidence']} why={r['why']} poc={r['poc_path']}")
            print(f"     {r['snippet'][:140]}")
    return 0


def cmd_get(args) -> int:
    conn = dbm.connect(paths.db_path(), readonly=True)
    try:
        card = dbm.get_card(conn, args.id)
    finally:
        conn.close()
    if card is None:
        print(json.dumps({"card": None, "error": "not_found", "untrusted": True}, ensure_ascii=False))
        return 1
    if args.raw:
        print(render_card(card))
        return 0
    _print(rankm.card_payload(card))
    return 0


def cmd_ingest(args) -> int:
    paths.ensure_dirs()
    stats = build_index(cards_dir=Path(args.cards) if args.cards else None)
    _print(stats)
    return 0


def cmd_validate(args) -> int:
    """离线校验 cards/，不写库。"""
    loaded = load_cards(Path(args.cards) if args.cards else None)
    bad = 0
    for p, card in loaded:
        issues = validate_card(card, artifacts_root=paths.kb_root())
        leaks = scan_secrets(render_card(card))
        if issues or leaks:
            bad += 1
            print(f"[!] {p.name}")
            for i in issues:
                print(f"    - {i}")
            if leaks:
                print(f"    - 密钥命中: {leaks}")
    print(f"checked={len(loaded)} problem={bad}")
    return 0 if bad == 0 else 2


def cmd_verify(args) -> int:
    """认领一张卡为 verified，写入 marker/证据（只改 card 文件，不改实验代码）。"""
    cards = Path(args.cards) if args.cards else paths.cards_dir()
    target = None
    for p in cards.glob("*.md"):
        c = card_from_text(p.read_text(encoding="utf-8"))
        if c.id.upper() == args.id.upper() or (c.cve or "").upper() == args.id.upper():
            target = (p, c)
            break
    if not target:
        print(f"未找到卡片: {args.id}")
        return 1
    p, card = target
    card.confidence = "verified"
    card.last_verified = args.date or __import__("datetime").date.today().isoformat()
    secs = card.sections()
    if args.marker:
        secs["预期 marker"] = args.marker[:200]
    if args.evidence:
        secs["证据指针"] = args.evidence[:150]
    if args.steps:
        secs["最小步骤"] = args.steps[:600]
    card.set_sections(secs)
    issues = validate_card(card, artifacts_root=paths.kb_root())
    if issues:
        print("校验未通过:", issues)
        return 2
    p.write_text(render_card(card), encoding="utf-8")
    print(f"已更新 {p.name} -> verified @ {card.last_verified}")
    return 0


def cmd_stats(args) -> int:
    conn = dbm.connect(paths.db_path(), readonly=True)
    try:
        _print(dbm.stats(conn))
    finally:
        conn.close()
    return 0


def cmd_check(args) -> int:
    from . import maintenance
    conn = dbm.connect(paths.db_path(), readonly=True)
    try:
        report = maintenance.check(conn, Path(args.cards) if args.cards else None)
    finally:
        conn.close()
    _print(report)
    return 0 if report["consistent"] else 2


def cmd_repair(args) -> int:
    from . import maintenance
    conn = dbm.connect(paths.db_path())
    try:
        dbm.init_db(conn)
        report = maintenance.repair(
            conn,
            cards_dir=Path(args.cards) if args.cards else None,
            artifacts_dir=Path(args.artifacts) if args.artifacts else None,
            apply=args.apply,
            sync_md=args.sync_md,
        )
    finally:
        conn.close()
    _print(report)
    return 0


def cmd_eval(args) -> int:
    from .evaluate import run_eval
    report = run_eval(Path(args.queries) if args.queries else None)
    _print(report)
    if args.out:
        Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"written: {args.out}", file=sys.stderr)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vuln-atlas", description="离线漏洞知识库 CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("search", help="检索卡片")
    s.add_argument("--query", "-q", default="")
    s.add_argument("--request", "-r", help="HTTP/curl/nmap 原文")
    s.add_argument("--product")
    s.add_argument("--version")
    s.add_argument("--cve")
    s.add_argument("--tags", nargs="*", default=[])
    s.add_argument("--top-k", type=int, default=5)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_search)

    g = sub.add_parser("get", help="按 id/cve 取卡")
    g.add_argument("id")
    g.add_argument("--raw", action="store_true", help="输出原始 Markdown")
    g.set_defaults(func=cmd_get)

    i = sub.add_parser("ingest", help="cards/*.md -> index.db")
    i.add_argument("--cards", help="cards 目录")
    i.set_defaults(func=cmd_ingest)

    v = sub.add_parser("validate", help="离线校验卡片")
    v.add_argument("--cards")
    v.set_defaults(func=cmd_validate)

    w = sub.add_parser("verify", help="把卡标记为 verified 并写入 marker/证据")
    w.add_argument("id")
    w.add_argument("--marker")
    w.add_argument("--evidence")
    w.add_argument("--steps")
    w.add_argument("--date")
    w.add_argument("--cards")
    w.set_defaults(func=cmd_verify)

    st = sub.add_parser("stats", help="库统计")
    st.set_defaults(func=cmd_stats)

    ck = sub.add_parser("check", help="体检：DB / cards 是否一致")
    ck.add_argument("--cards")
    ck.set_defaults(func=cmd_check)

    rp = sub.add_parser("repair", help="修复标题 / 关联元数据 artifact / 导出缺失卡 / 同步概念表")
    rp.add_argument("--cards")
    rp.add_argument("--artifacts")
    rp.add_argument("--apply", action="store_true", help="不传则只统计，不落盘")
    rp.add_argument("--sync-md", action="store_true",
                    help="已有 md 与 DB 不一致时一并重写（cards/ 镜像 DB）")
    rp.set_defaults(func=cmd_repair)

    ev = sub.add_parser("eval", help="跑检索评测")
    ev.add_argument("--queries")
    ev.add_argument("--out")
    ev.set_defaults(func=cmd_eval)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
