"""本地只读 Web UI：调用与 MCP 相同的检索层（router.build_query + rank.search）。"""
from __future__ import annotations

import argparse
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from vuln_atlas import db as dbm
from vuln_atlas import paths, rank as rankm
from vuln_atlas.router import build_query

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
DB_PATH: Path | None = None


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnAtlas/0.2"

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
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _conn(self):
        return dbm.connect(DB_PATH or paths.db_path(), readonly=True)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, (WEB / "index.html").read_bytes(), "text/html; charset=utf-8")
            return
        if parsed.path == "/api/search":
            params = parse_qs(parsed.query)
            first = lambda k: (params.get(k) or [""])[0]  # noqa: E731
            tags = [t for t in first("tags").split(",") if t.strip()]
            try:
                top_k = int(first("top_k") or "8")
            except ValueError:
                top_k = 8
            q = build_query(
                query=first("q"),
                request=first("request") or None,
                product=first("product") or None,
                version=first("version") or None,
                cve=first("cve") or None,
                tags=tags,
            )
            conn = self._conn()
            try:
                res = rankm.search(conn, q, top_k=max(1, min(10, top_k)))
            finally:
                conn.close()
            self._json(200, res)
            return
        if parsed.path == "/api/card":
            card_id = (parse_qs(parsed.query).get("id") or [""])[0]
            conn = self._conn()
            try:
                card = dbm.get_card(conn, card_id)
            finally:
                conn.close()
            if card is None:
                self._json(404, {"error": "not_found", "id": card_id})
            else:
                self._json(200, rankm.card_payload(card))
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
    parser.add_argument("--db", default=None, help="默认 VULN_ATLAS_DB 或 <kb>/index.db")
    args = parser.parse_args()
    DB_PATH = Path(args.db).resolve() if args.db else paths.db_path()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"VulnAtlas UI: http://{args.host}:{args.port}/  db={DB_PATH}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
