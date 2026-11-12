from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from vuln_atlas.db import init_db
from vuln_atlas.search import get_card, search

TOOLS = [
    {
        "name": "wiki_search",
        "description": "Search offline vulnerability cards by CVE, product, version, tags or text.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "product": {"type": "string"},
                "version": {"type": "string"},
                "cve": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "top_k": {"type": "integer", "default": 5},
            },
        },
    },
    {
        "name": "wiki_get",
        "description": "Read one vulnerability card by id. Body is capped to 8KB.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
    },
]


def _db():
    return init_db(os.environ.get("VULN_ATLAS_DB", "index.db"))


def _call(name: str, arguments: dict) -> dict:
    conn = _db()
    if name == "wiki_search":
        return {"results": search(
            conn,
            query=str(arguments.get("query") or ""),
            product=arguments.get("product"),
            version=arguments.get("version"),
            cve=arguments.get("cve"),
            tags=list(arguments.get("tags") or []),
            top_k=int(arguments.get("top_k") or 5),
        )}
    if name == "wiki_get":
        card = get_card(conn, str(arguments.get("id") or ""))
        if card is None:
            return {"error": "not_found"}
        card["body"] = str(card.get("body") or "")[:8192]
        return {"card": card}
    raise ValueError(f"unknown tool: {name}")


def _response(request: dict) -> dict | None:
    method = request.get("method")
    request_id = request.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": request_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "vuln-atlas", "version": "0.1.0"},
        }}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = request.get("params") or {}
        try:
            result = _call(str(params.get("name") or ""), params.get("arguments") or {})
            return {"jsonrpc": "2.0", "id": request_id, "result": {
                "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}],
                "isError": False,
            }}
        except Exception as exc:  # noqa: BLE001
            return {"jsonrpc": "2.0", "id": request_id, "result": {
                "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
                "isError": True,
            }}
    if method in {"notifications/initialized", "notifications/cancelled"}:
        return None
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "method not found"}}


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = _response(request)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
