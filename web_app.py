from __future__ import annotations

import argparse
import json
import mimetypes
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from vuln_atlas.db import connect
from vuln_atlas.search import get_card, search

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
DB_PATH = os.environ.get("VULN_ATLAS_DB", str(ROOT / "demo.db"))


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnAtlas/0.1"

    def log_message(self, fmt: str, *args) -> None:
        print("%s - %s" % (self.address_string(), fmt % args))

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            index = WEB / "index.html"
            self._send(200, index.read_bytes(), "text/html; charset=utf-8")
            return
        if parsed.path == "/api/search":
            params = parse_qs(parsed.query)
            q = (params.get("q") or [""])[0]
            product = (params.get("product") or [""])[0] or None
            version = (params.get("version") or [""])[0] or None
            cve = (params.get("cve") or [""])[0] or None
            tags = [tag for tag in (params.get("tags") or [""])[0].split(",") if tag.strip()]
            try:
                top_k = int((params.get("top_k") or ["8"])[0])
            except ValueError:
                top_k = 8
            conn = connect(DB_PATH)
            try:
                results = search(conn, query=q, product=product, version=version, cve=cve, tags=tags, top_k=top_k)
            finally:
                conn.close()
            self._json(200, {"results": results, "db": DB_PATH})
            return
        if parsed.path == "/api/card":
            card_id = (parse_qs(parsed.query).get("id") or [""])[0]
            conn = connect(DB_PATH)
            try:
                card = get_card(conn, card_id)
            finally:
                conn.close()
            if card is None:
                self._json(404, {"error": "not_found", "id": card_id})
            else:
                card["body"] = str(card.get("body") or "")[:8192]
                self._json(200, {"card": card})
            return
        candidate = (WEB / parsed.path.lstrip("/")).resolve()
        if str(candidate).startswith(str(WEB.resolve())) and candidate.is_file():
            ctype = mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
            self._send(200, candidate.read_bytes(), ctype)
            return
        self._json(404, {"error": "not_found"})


def main() -> int:
    global DB_PATH
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default=DB_PATH)
    args = parser.parse_args()
    DB_PATH = args.db
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"VulnAtlas UI: http://{args.host}:{args.port}/  db={DB_PATH}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
