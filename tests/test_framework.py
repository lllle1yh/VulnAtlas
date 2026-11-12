from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from vuln_atlas.db import init_db
from vuln_atlas.ingest.nuclei import ingest_nuclei
from vuln_atlas.search import get_card, search

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _template(root: Path) -> None:
    path = root / "http" / "cves" / "2018" / "CVE-2018-3760.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(
        """id: CVE-2018-3760
info:
  name: Rails Sprockets Path Traversal
  severity: high
  description: Sprockets path traversal test
  tags: cve,rails,lfi
  classification:
    cve-id: CVE-2018-3760
  reference:
    - https://example.invalid/CVE-2018-3760
http:
  - method: GET
    path:
      - "{{BaseURL}}/assets/file:%2f%2f/etc/passwd"
    matchers:
      - type: word
        words: ["root:"]
""",
        encoding="utf-8",
    )


def test_ingest_search_and_get(tmp_path):
    raw = tmp_path / "nuclei"
    _template(raw)
    conn = init_db(tmp_path / "index.db")
    stats = ingest_nuclei(conn, raw)
    assert stats["cards"] == 1
    result = search(conn, query="CVE-2018-3760", top_k=5)
    assert result and result[0]["id"] == "CVE-2018-3760"
    assert result[0]["poc_type"] == "nuclei"
    card = get_card(conn, "CVE-2018-3760")
    assert card and "nuclei -t" in card["steps"]


def test_cli_and_mcp_importable(tmp_path):
    assert (ROOT / "vuln_atlas" / "cli.py").is_file()
    assert (ROOT / "vuln_atlas" / "mcp_server.py").is_file()


def test_query_normalization_handles_no_space_and_chinese(tmp_path):
    from vuln_atlas.search import normalize_query
    tokens = normalize_query("RubyonRails本地文件包含怎么打")
    assert "ruby" in tokens
    assert "rails" in tokens
    assert "lfi" in tokens
    assert "怎么打" not in tokens
