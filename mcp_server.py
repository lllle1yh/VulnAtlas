#!/usr/bin/env python3
"""计划 §12 的顶层 MCP 入口；实现在 vuln_atlas/mcp_server.py。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vuln_atlas.mcp_server import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
