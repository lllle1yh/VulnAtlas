"""检索评测（§10.1）：50 条查询，top-1 / top-3 / 空结果率 / 延迟。"""
from __future__ import annotations

import json
import statistics
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import db as dbm
from . import paths
from . import rank as rankm
from .router import build_query

DEFAULT_QUERIES = paths.repo_root() / "data" / "eval-queries.json"

TARGETS = {
    "cve_exact": {"top1": 0.95, "top3": 0.95},
    "product_version": {"top3": 0.80},
    "zh": {"top3": 0.70},
    "fuzzy": {"top3": 0.70},
    "overall": {"empty_rate": 0.10},
}


def run_eval(queries_file: Optional[Path] = None, top_k: int = 5) -> Dict[str, Any]:
    qf = Path(queries_file) if queries_file else DEFAULT_QUERIES
    cases = json.loads(qf.read_text(encoding="utf-8"))
    conn = dbm.connect(paths.db_path(), readonly=True)
    by_kind: Dict[str, List[Dict[str, Any]]] = {}
    rows: List[Dict[str, Any]] = []
    try:
        for case in cases:
            q = build_query(
                query=case.get("query", ""),
                product=case.get("product"),
                version=case.get("version"),
                cve=case.get("cve"),
                tags=case.get("tags") or [],
            )
            t0 = time.perf_counter()
            res = rankm.search(conn, q, top_k=top_k)
            dt = (time.perf_counter() - t0) * 1000.0
            ids = [r["id"] for r in res["results"]]
            expect = case.get("expect")
            row = {
                "id": case.get("id"),
                "kind": case.get("kind"),
                "query": case.get("query"),
                "product": case.get("product"),
                "version": case.get("version"),
                "expect": expect,
                "got": ids[:3],
                "top1": bool(ids) and ids[0] == expect,
                "top3": expect in ids[:3] if expect else None,
                "empty": not ids,
                "ms": round(dt, 2),
            }
            rows.append(row)
            by_kind.setdefault(case.get("kind", "-"), []).append(row)
    finally:
        conn.close()

    summary: Dict[str, Any] = {}
    for kind, items in by_kind.items():
        n = len(items)
        summary[kind] = {
            "n": n,
            "top1": round(sum(1 for r in items if r["top1"]) / n, 4),
            "top3": round(sum(1 for r in items if r["top3"]) / n, 4),
            "empty_rate": round(sum(1 for r in items if r["empty"]) / n, 4),
            "p50_ms": round(statistics.median(r["ms"] for r in items), 2),
            "p95_ms": round(sorted(r["ms"] for r in items)[max(0, int(n * 0.95) - 1)], 2),
        }
    n_all = len(rows)
    summary["overall"] = {
        "n": n_all,
        "top1": round(sum(1 for r in rows if r["top1"]) / n_all, 4),
        "top3": round(sum(1 for r in rows if r["top3"]) / n_all, 4),
        "empty_rate": round(sum(1 for r in rows if r["empty"]) / n_all, 4),
        "p50_ms": round(statistics.median(r["ms"] for r in rows), 2),
        "p95_ms": round(sorted(r["ms"] for r in rows)[max(0, int(n_all * 0.95) - 1)], 2),
    }

    verdict = {}
    for kind, targets in TARGETS.items():
        s = summary.get(kind)
        if not s:
            continue
        checks = {}
        for metric, target in targets.items():
            key = "empty_rate" if metric == "empty_rate" else metric
            val = s[key]
            checks[metric] = {
                "value": val, "target": target,
                "pass": (val <= target if metric == "empty_rate" else val >= target),
            }
        verdict[kind] = checks

    misses = [r for r in rows if r["top3"] is False]
    return {
        "queries_file": str(qf),
        "db": str(paths.db_path()),
        "top_k": top_k,
        "summary": summary,
        "targets": verdict,
        "misses": misses,
        "cases": rows,
    }
