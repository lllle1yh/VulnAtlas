"""离线快照下载器（只在 ingest 时联网，运行时永不联网）。

用法：
    python3 -m vuln_atlas.ingest.fetch kev
    python3 -m vuln_atlas.ingest.fetch epss cwe
    python3 -m vuln_atlas.ingest.fetch --list
"""
from __future__ import annotations

import argparse
import gzip
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from .. import paths
from .common import Manifest

UA = "vuln-atlas/0.1 (+offline-kb; snapshot script)"

# source -> (url, 目标相对路径, license, 是否可再分发, 备注)
SOURCES: Dict[str, tuple] = {
    "kev": ("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "kev/known_exploited_vulnerabilities.json",
            "public-domain-us-gov", True, ""),
    "epss": ("https://epss.cyentia.com/epss_scores-current.csv.gz",
             "epss/epss_scores-current.csv.gz",
             "first-epss-open (attribution required)", False, "每日更新，强依赖当天快照"),
    "cwe": ("https://cwe.mitre.org/data/csv/1000.csv.zip",
            "cwe/cwe-1000.csv.zip", "CC-BY-4.0", True, "只用标签"),
    "exploitdb_csv": ("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
                      "exploitdb/files_exploits.csv", "GPL-2.0", False, "只取 CSV 映射"),
}


def snapshot(source: str, timeout: int = 120, out_root: Optional[Path] = None) -> Path:
    if source not in SOURCES:
        raise SystemExit(f"未知数据源: {source}，可选: {', '.join(SOURCES)}")
    url, rel, lic, redist, note = SOURCES[source]
    root = out_root or paths.raw_dir()
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    print(f"[fetch] {source}: {url}")
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
    print(f"[write] {dest} {dest.stat().st_size} bytes")

    m = Manifest(paths.manifest_path())
    m.add_snapshot(source, url, dest, license=lic, redistribute=redist, status="ok", note=note)
    m.save()
    return dest


def snapshot_nvd(year: int, timeout: int = 300, out_root: Optional[Path] = None) -> Path:
    url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
    root = out_root or paths.raw_dir()
    dest = root / "nvd" / f"nvdcve-2.0-{year}.json.gz"
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    print(f"[fetch] nvd {year}: {url}")
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
    m = Manifest(paths.manifest_path())
    m.add_snapshot(f"nvd-{year}", url, dest, license="public-domain-us-gov",
                   redistribute=True, status="ok")
    m.save()
    return dest


def mark_unavailable(source: str, status: str, note: str, license: str = "") -> None:
    m = Manifest(paths.manifest_path())
    m.set_source_status(source, status, note, license=license)
    m.save()
    print(f"[manifest] {source} -> {status}: {note}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="fetch", description="下载数据源离线快照")
    ap.add_argument("sources", nargs="*", help="kev / epss / cwe / exploitdb_csv / nvd-YYYY")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args(argv)
    if args.list or not args.sources:
        for k, v in SOURCES.items():
            print(f"{k:15s} {v[0]}")
        return 0
    for s in args.sources:
        if s.startswith("nvd-"):
            snapshot_nvd(int(s.split("-", 1)[1]))
        else:
            snapshot(s)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
