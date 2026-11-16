#!/usr/bin/env python3
"""计划 §12 的顶层入口；实现在 vuln_atlas/cli.py。

    python3 cli.py search -q "log4j"
    python3 cli.py get CVE-2021-44228
    python3 cli.py ingest
    python3 cli.py verify CVE-2018-3760 --marker "..."
    python3 cli.py stats
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vuln_atlas.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
