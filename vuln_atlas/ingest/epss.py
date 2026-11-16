"""FIRST EPSS 解析器：cve -> (epss, percentile)。CSV.GZ，首行是 #model_version 注释。"""
from __future__ import annotations

import csv
import gzip
import io
from pathlib import Path
from typing import Dict, Iterator


def parse(path: Path) -> Iterator[Dict[str, object]]:
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                continue
            header = line.rstrip("\n").split(",")
            break
        else:
            return
        # gzip 文本流继续交给 DictReader 读剩余行
        reader = csv.DictReader(f, fieldnames=header)
        for row in reader:
            cve = (row.get("cve") or "").strip().upper()
            if not cve:
                continue
            try:
                epss = float(row.get("epss") or 0)
                pct = float(row.get("percentile") or 0)
            except ValueError:
                continue
            yield {"cve": cve, "epss": epss, "epss_percentile": pct}


def load_index(path: Path, min_epss: float = 0.0) -> Dict[str, Dict[str, object]]:
    out = {}
    for r in parse(path):
        if r["epss"] >= min_epss:
            out[r["cve"]] = r
    return out
