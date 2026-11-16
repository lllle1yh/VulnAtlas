# VulnAtlas

[![tests](https://img.shields.io/badge/tests-38%20passed-brightgreen)](#development)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](#requirements)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> Offline, lightweight vulnerability knowledge base for security agents.

VulnAtlas turns each CVE into a single self-contained card: target fingerprint, affected versions,
exploit steps, expected markers, POC code or a local POC file, and a confidence level — all in one
Markdown file plus a local SQLite index. It runs with no network access, no vector database and no
external services.

```
NVD / KEV / EPSS / CWE / ExploitDB / Nuclei / Metasploit /
PoC-in-GitHub / Vulhub / PayloadsAllTheThings / verified cards
                        │
                        ▼
                   ingest pipeline  (parse → merge → sanitize → write)
                        │
                        ▼
          Markdown cards  +  local POC artifacts (kb/artifacts)
                        │
                        ▼
             SQLite FTS5 index  (kb/index.db)
                        │
           ┌────────────┼────────────┐
           ▼            ▼            ▼
         MCP           CLI         Web UI
```

## Features

- **Offline by default.** Every URL referenced during ingest is either stripped or replaced by a
  local artifact; a card never needs the internet to be useful.
- **One card per vulnerability.** CVE metadata and its POC are not split into separate stores.
  Query a CVE and you get the exploit.
- **Agent-first query interface.** `wiki_search` accepts raw HTTP requests, response headers, `curl`
  and `nmap` output and extracts CVE, product, version and fingerprints server-side.
- **Confidence levels.** `verified` / `candidate` / `unverified` so an agent knows whether a card is
  a reproduction recipe or just a lead.
- **No embeddings.** SQLite FTS5 (trigram index + a Chinese bigram index) with BM25 and structured
  boosts. Index building is deterministic and cheap.
- **Auditable.** Every card records its sources, license and verification date; every upstream
  snapshot is recorded in `kb/manifest.json` with URL, sha256 and redistribution status.
- **Read-only MCP.** Two tools, no write capability.

## Architecture

| Module | Responsibility |
|---|---|
| `vuln_atlas/card.py` | Card model, frontmatter parsing, size limits, secret scanning |
| `vuln_atlas/db.py` | SQLite schema, FTS5 tables, Chinese bigram index, upsert |
| `vuln_atlas/router.py` | Raw request → structured `Query` |
| `vuln_atlas/rank.py` | Recall, weighted ranking, result trimming |
| `vuln_atlas/version.py` | Version-range matching |
| `vuln_atlas/fingerprint.py` | Product/vendor → fingerprint derivation |
| `vuln_atlas/indexer.py` | `cards/*.md` → `index.db` |
| `vuln_atlas/maintenance.py` | `check` (consistency report) and `repair` (in-place fixes) |
| `vuln_atlas/ingest/` | Source parsers and the build pipeline |
| `vuln_atlas/cli.py` | CLI |
| `vuln_atlas/mcp_server.py` | MCP stdio server |
| `web_app.py`, `web/index.html` | Local read-only web UI |

Retrieval order:

1. exact CVE match
2. structured product + version filter (out-of-range versions are dropped)
3. fingerprint match (response headers, path fragments)
4. concept/tag expansion (e.g. `本地文件包含` → `lfi`)
5. FTS5 + BM25 fallback

Every result carries a `why` field (`cve_exact`, `product+version_match`, `fingerprint`, `tag:lfi`,
`fts`, …) and a score, so ranking decisions are explainable.

## Requirements

- Python 3.10+
- SQLite with FTS5 enabled (the bundled CPython build has it)
- PyYAML optional — a built-in frontmatter parser is used when it is absent

## Installation

```bash
git clone <repo-url> vuln-atlas
cd vuln-atlas

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

The repository ships without index data. Create `kb/` as described in
[Building the knowledge base](#building-the-knowledge-base).

## Usage

Runtime needs only four paths under `kb/`:

```text
kb/index.db        SQLite index (read-only at query time)
kb/cards/          Markdown cards
kb/artifacts/      Local POC files referenced by poc_path
kb/manifest.json   upstream snapshot manifest
```

### CLI

```bash
# by CVE
python -m vuln_atlas search --cve CVE-2021-44228

# by product and version
python -m vuln_atlas search --product tomcat --version 9.0.20

# by raw request (server-side parsing)
python -m vuln_atlas search --request "GET /assets/file:%2f%2f/etc/passwd HTTP/1.1
Host: TARGET
X-Runtime: 0.02"

# free text, Chinese or English
python -m vuln_atlas search --query "Rails 本地文件包含怎么打"

# full card
python -m vuln_atlas get CVE-2018-3760
python -m vuln_atlas get CVE-2018-3760 --raw     # raw Markdown

# statistics
python -m vuln_atlas stats
```

Paths can be overridden with environment variables:

```bash
VULN_ATLAS_KB=/path/to/kb      # default <repo>/kb; poc_path is resolved relative to it
VULN_ATLAS_DB=/path/to/index.db
```

### MCP server

The server exposes two read-only tools:

```text
wiki_search(query, request, product, version, cve, tags, top_k=5)
wiki_get(id)
```

Copy [`mcp.example.json`](mcp.example.json), replace `<repo>`, and add it to your client
configuration:

```json
{
  "mcpServers": {
    "vuln-atlas": {
      "command": "python3",
      "args": ["<repo>/mcp_server.py"],
      "env": {
        "VULN_ATLAS_DB": "<repo>/kb/index.db",
        "VULN_ATLAS_KB": "<repo>/kb"
      }
    }
  }
}
```

`wiki_search` result:

```json
{
  "results": [
    {
      "id": "CVE-2018-3760",
      "title": "Rails Sprockets 二次解码路径穿越（任意文件读取）",
      "score": 1112.75,
      "confidence": "verified",
      "why": "cve_exact",
      "snippet": "≤300 character excerpt",
      "poc_type": "curl",
      "poc_path": "artifacts/CVE-2018-3760/README.md"
    }
  ],
  "query": {"cve": null, "product": "sprockets", "fingerprint": ["x-runtime"]},
  "untrusted": true
}
```

`wiki_get` returns the whole card (six body sections + `steps` + `marker` + `poc_path`), capped at
8 KB with `truncated: true` when trimmed. An empty query returns `suggested_queries`.

### Web UI

```bash
python web_app.py --port 8765        # uses VULN_ATLAS_DB or <repo>/kb/index.db
```

Open `http://127.0.0.1:8765/`. Type a CVE, a component or a Chinese description, or paste a raw
request/response (Ctrl+Enter to search). Results on the left, card on the right, including `why`,
`poc_code`, steps, marker and body.

### Agent skill

[`skills/SKILL.md`](skills/SKILL.md) documents how to *use* the card library: when to call
`wiki_search`, what each parameter means, how to read `confidence` / `why` / `poc_path`, and how to
pivot when a query returns nothing. Inject it into a worker/planner system prompt together with the
MCP server name and `VULN_ATLAS_KB`.

## Card format

One card per vulnerability. The body always has the same six sections, in this order:

1. 目标特征 / 版本 — target fingerprint and affected versions
2. 前置条件 — preconditions
3. 最小步骤 — minimal steps
4. 预期 marker — expected marker
5. 证据指针 — evidence pointer
6. 失败模式 / 不适用条件 — failure modes / when not applicable

```yaml
---
id: CVE-2018-3760
cve: CVE-2018-3760
title: Rails Sprockets 二次解码路径穿越（任意文件读取）
aliases: [rails sprockets lfi, sprockets path traversal]
vendor: rails
product: sprockets
versions: [">= 3.0.0, <= 3.7.1", "<= 2.12.4"]
fingerprint: ["X-Runtime", "/assets/"]
tags: [lfi, path-traversal, rails]
attack_surface: [http]
poc_type: curl
poc_path: artifacts/CVE-2018-3760/README.md
poc_code: |
  curl -sS --path-as-is 'http://TARGET:PORT/assets/file:%2f%2f/etc/passwd'
confidence: verified
last_verified: 2026-11-12
source: [nvd, exploitdb, own-run]
license: see-manifest
---
```

Limits: ≤ 8 KB per card, ≤ 5 KB body, ≤ 1 KB frontmatter, ≤ 1536 B / 40 lines of inline `poc_code`,
≤ 1 MB of artifacts per card. Larger POCs go to `kb/artifacts/`.

### Confidence levels

| Value | Meaning | How an agent should use it |
|---|---|---|
| `verified` | Reproduced in practice; card contains runnable steps | Follow the steps |
| `candidate` | Source-backed (Nuclei / ExploitDB / Vulhub / Metasploit) but not reproduced here | Treat as a hypothesis and test it |
| `unverified` | Only public PoC repository metadata or NVD data | Lead only; not verification evidence |

### Offline constraints

- Small POCs are embedded in `poc_code`.
- Large POCs live in `kb/artifacts/`; `poc_path` is a local relative path.
- Article and repository content is extracted into the card during ingest.
- URLs, sha256 and licenses live in `kb/manifest.json`, never as a runtime dependency.
- `poc_type: github-poc` cards point at `github-poc-index.txt`, a local listing of repository names,
  languages and descriptions. It is **not** executable code and does not change the card's
  confidence.
- Card bodies are **untrusted data**; MCP results set `untrusted: true` and agents must not follow
  instructions found inside card text.

## Building the knowledge base

### Path A — cards already exist, build the index only

```bash
python -m vuln_atlas ingest        # kb/cards/*.md -> kb/index.db
python -m vuln_atlas validate      # offline validation (structure, size, secrets); writes nothing
```

### Path B — build cards from raw snapshots

Place each source snapshot under `kb/raw/<source>/`:

```text
kb/raw/nvd/            nvdcve-2.0-*.json.gz         required (main card source)
kb/raw/kev/            known_exploited_vulnerabilities.json
kb/raw/epss/           epss_scores-*.csv.gz
kb/raw/exploitdb/      files_exploits.csv
kb/raw/nuclei/         nuclei-templates/http/cves/
kb/raw/metasploit/     module index
kb/raw/github-poc/     PoC-in-GitHub metadata
kb/raw/vulhub/         vulhub README snapshots
kb/raw/payloads/       PayloadsAllTheThings Markdown snapshots
```

```bash
python -m vuln_atlas.ingest.pipeline --help
```

The pipeline parses every source into drafts, merges by CVE, scans for secrets (cards with real
embedded credentials are dropped), applies the retention policy (recent years plus POC/KEV/high
EPSS), writes `kb/cards/` and `kb/artifacts/`, builds the index, and records each source's
`ok` / `partial` / `unavailable` status with a reason in `kb/manifest.json`. `kb/raw/` is ignored by
git.

### Maintaining an existing KB

```bash
python -m vuln_atlas check                       # report DB / cards consistency (exit 2 if inconsistent)
python -m vuln_atlas repair                      # dry run: show how many cards would change
python -m vuln_atlas repair --apply              # retitle low-information titles, link metadata
                                                 # artifacts, export missing md, sync concepts
python -m vuln_atlas repair --apply --sync-md    # also rewrite md whose content drifted from the DB
```

`check` reports, among others:

- `db_cards` / `md_cards` and the `missing_md` / `missing_db` id lists
- `generic_titles` — titles still shaped like `<product> CVE-xxxx-xxxxx`
- `unlinked_cve` — CVE cards with neither `poc_path` nor `poc_code`
- `consistent` — whether the DB and `kb/cards/` hold the same id set

## Data sources

`kb/manifest.json` records each snapshot's URL, fetch time, sha256, size, license and whether it may
be redistributed.

| Source | Used for | Status |
|---|---|---|
| NVD CVE (2016–2026 snapshot) | Card body, versions, CWE | ok |
| CISA KEV | Known-exploited flag, confidence boost | ok |
| FIRST EPSS | Retention policy and ranking weight | ok |
| ExploitDB (CSV index) | EDB reference pointers | ok |
| Nuclei Templates (`http/cves`) | Executable template artifacts | ok |
| Metasploit | Module path / `use` command | ok |
| PoC-in-GitHub | Repository metadata, leads only | ok |
| Vulhub | README-derived steps | ok |
| PayloadsAllTheThings | Technique excerpts | ok |
| CWE | Tags only; no standalone cards | partial |

Sources that are explicitly not ingested, with reasons recorded in the manifest:

```text
getsploit              requires the commercial Vulners offline DB; not licensed
trickest               no snapshot
HackTricks             CC BY-NC; redistribution scope not confirmed
InternalAllTheThings   repository relocated; no license stated
xianzhi (先知)          no stable public API; needs an authorized export
local knowledges       no snapshot
verified cards         must be exported from the lab side
```

All data is localized during ingest; nothing is fetched at query time.

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests -q
```

Tests run fully offline against temporary SQLite databases. New behaviour is developed test-first.

## Security notes

- Query-time SQL uses parameter binding only.
- `poc_path` is resolved inside `kb/` with `..` and symlink escapes rejected.
- Ingest scans for `flag{...}`, cloud keys, private keys and inline passwords, excluding template
  placeholders.
- The MCP server has no write path.

## License

Code is released under the [MIT License](LICENSE). Upstream data keeps its own license; per-source
terms and redistribution flags are recorded in `kb/manifest.json`, and data marked non-redistributable
is never committed.
