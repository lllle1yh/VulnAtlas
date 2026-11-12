from __future__ import annotations

import argparse
import json
from pathlib import Path

from vuln_atlas.db import init_db
from vuln_atlas.ingest.nuclei import ingest_nuclei
from vuln_atlas.search import get_card, search


def main() -> int:
    parser = argparse.ArgumentParser(prog="vuln-atlas")
    parser.add_argument("--db", default="index.db")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init")

    p_ingest = sub.add_parser("ingest-nuclei")
    p_ingest.add_argument("--root", required=True)

    p_search = sub.add_parser("search")
    p_search.add_argument("query", nargs="?", default="")
    p_search.add_argument("--product")
    p_search.add_argument("--version")
    p_search.add_argument("--cve")
    p_search.add_argument("--tag", action="append", default=[])
    p_search.add_argument("--top-k", type=int, default=5)

    p_get = sub.add_parser("get")
    p_get.add_argument("id")

    args = parser.parse_args()
    conn = init_db(args.db)
    if args.command == "init":
        print(json.dumps({"db": str(Path(args.db).resolve())}, ensure_ascii=False))
        return 0
    if args.command == "ingest-nuclei":
        print(json.dumps(ingest_nuclei(conn, args.root), ensure_ascii=False))
        return 0
    if args.command == "search":
        print(json.dumps(search(
            conn, query=args.query, product=args.product, version=args.version,
            cve=args.cve, tags=args.tag, top_k=args.top_k,
        ), ensure_ascii=False, indent=2))
        return 0
    if args.command == "get":
        card = get_card(conn, args.id)
        if card is None:
            print(json.dumps({"error": "not_found", "id": args.id}, ensure_ascii=False))
            return 1
        print(json.dumps(card, ensure_ascii=False, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
