# VulnAtlas

离线、面向安全 Agent 的漏洞知识库：每个 CVE 一张卡，包含指纹、影响版本、内置 POC/最小步骤和验证 marker。SQLite FTS5 + MCP，不依赖向量化和外部服务。

- 仓库：https://github.com/lllle1yh/VulnAtlas
- 本地目录：`C:\Users\30209\Desktop\迭代工作区\VulnAtlas`

## 为什么做这个

比赛环境经常断网，Agent 不能依赖 WebFetch/WebSearch。  
常见做法是把 POC 和文章放在本地目录里让 Agent `grep`，但这样缺排序、缺版本过滤、缺结构，Agent 很难快速找到“这个目标的 CVE、POC、最小步骤”。

VulnAtlas 把这些问题收成一张卡：

```text
一个 CVE / 漏洞一张卡
  指纹 + 影响版本
  + 本地 POC / 最小命令
  + 预期 marker
  + 来源 / 置信度 / 最后验证时间
```

运行时只查一个 SQLite 文件。

## 特点

- **离线**：卡片内容来自本地 artifacts，不依赖外链；断网可用。
- **轻量**：一个 SQLite 文件 + 一个薄 MCP 服务；不跑容器、不跑 ES/MongoDB。
- **不向量化**：SQLite FTS5 + BM25 + 结构化字段；不做 embedding、不做向量库。
- **面向 Agent**：MCP 只暴露两个只读工具，返回小、结构化、带 `why` 和 `confidence`。
- **可审计**：每张卡保留来源、置信度、最后验证时间；URL/license/sha256 只放 manifest。

## 架构

```text
数据源快照 raw/
    │
    ├─ NVD / KEV / EPSS / CWE
    ├─ ExploitDB / Nuclei / Metasploit / getsploit
    ├─ GitHub PoC / Vulhub
    ├─ HackTricks / PayloadsAllTheThings / InternalAllTheThings
    ├─ 先知社区授权导出
    └─ 现有卡片 / 本系统验证卡
    │
    ▼
ingest 管线
    │  归一化 CVE、组件、版本、POC、provenance
    ▼
cards/*.md                 Markdown 卡，人工可读、可 review
artifacts/                 POC 原文/脚本，本地文件
index.db                   SQLite FTS5，唯一查询入口
    │
    ├─ CLI: search / get / ingest
    └─ MCP: wiki_search / wiki_get
```

## 卡片模型

一张卡同时包含 CVE 元数据和 POC，不拆成“CVE 表 + POC 表”。

```yaml
---
id: CVE-2018-3760
cve: CVE-2018-3760
title: Rails/Sprockets 二次解码路径穿越
aliases:
  - rails sprockets lfi
  - sprockets path traversal
vendor: rails
product: sprockets
versions:
  - "<= 3.7.1"
fingerprint:
  - "X-Runtime"
  - "Ruby on Rails"
tags: [lfi, path-traversal, rails]
attack_surface: [http]
poc_type: curl
poc_path: artifacts/CVE-2018-3760/README.md   # 本地文件，不是外链
poc_code: |
  curl -sS --path-as-is 'http://TARGET:PORT/assets/file:%2f%2f/etc/passwd'
confidence: verified
last_verified: 2026-11-09
source:
  - nvd
  - exploitdb
  - own-run
---
```

正文：

```text
目标特征 / 版本
前置条件
最小步骤
预期 marker
证据指针
失败模式
```

### 离线内容硬约束

卡片里不能出现“需要联网才能打开”的链接作为内容：

- 不写“参考 https://...”
- 不把 GitHub / 博客 / issue 链接当步骤
- 小 POC 直接写进 `poc_code`
- 大 POC 放本地 `artifacts/`，`poc_path` 指向本地文件
- URL / license / sha256 / 抓取时间只写 `manifest.json`

## 查询

不做向量化。查询链路：

```text
1. CVE 精确匹配
2. product + version 版本过滤
3. path / header / fingerprint 匹配
4. concepts / alias 扩展
5. FTS5 + BM25 兜底
```

支持自然语言和原始请求：

```text
CVE-2018-3760怎么利用
RubyonRails本地文件包含怎么打
GET /assets/file:%2f%2f/etc/passwd HTTP/1.1
curl 'http://TARGET/assets/file:%2f%2f/etc/passwd'
```

服务端负责：

- 识别 CVE
- 提取 product/version/path/header
- 概念扩展：`本地文件包含 → lfi`、`路径穿越 → path traversal`
- 产品名从卡片词表动态切词，不硬编码
- BM25 字段权重

## MCP

只读工具：

```text
wiki_search(
  query, request, product, version, cve, tags, top_k
)

wiki_get(id)
```

返回示例：

```json
{
  "results": [
    {
      "id": "CVE-2018-3760",
      "title": "Rails/Sprockets 二次解码路径穿越",
      "score": 18.2,
      "confidence": "verified",
      "why": "cve_exact",
      "snippet": "<= 300 chars",
      "poc_type": "curl",
      "poc_path": "artifacts/CVE-2018-3760/README.md"
    }
  ]
}
```

`wiki_get` 返回一张卡，body 最多 8KB，POC 只给本地路径。

## CLI

```bash
python -m vuln_atlas.cli --db index.db init
python -m vuln_atlas.cli --db index.db ingest-nuclei --root raw/nuclei-templates
python -m vuln_atlas.cli --db index.db search "RubyonRails本地文件包含怎么打" --top-k 5
python -m vuln_atlas.cli --db index.db get CVE-2018-3760
```

## 本地 UI

```bash
python web_app.py --db demo.db --port 8765
```

打开：

```text
http://127.0.0.1:8765/
```

## 目录

```text
vuln_atlas/
  db.py               SQLite schema / FTS5
  search.py           查询归一化 / 路由 / BM25
  ingest/nuclei.py    nuclei-templates 解析器
  cli.py              CLI
  mcp_server.py       MCP stdio server
web_app.py            本地 HTTP + Web UI
web/index.html        前端
raw/                  数据源快照（不提交大文件）
cards/                Markdown 卡
artifacts/            本地 POC
tests/
```

## 当前状态

- [x] SQLite FTS5（trigram）+ 卡片 upsert
- [x] nuclei-templates ingest
- [x] CLI `search` / `get` / `ingest-nuclei`
- [x] MCP `wiki_search` / `wiki_get` 骨架
- [x] 本地 Web UI
- [x] 中文/无空格查询归一化
- [ ] NVD / KEV / EPSS / CWE ingest
- [ ] ExploitDB / Metasploit / getsploit ingest
- [ ] GitHub PoC / Vulhub / 文章 ingest
- [ ] concepts 数据表
- [ ] request_parser（HTTP/curl/nmap）
- [ ] skill 文件与 worker 注入

## 开发

```bash
python -m pytest tests -q
```

依赖：

```text
Python >= 3.10
PyYAML >= 6.0
SQLite with FTS5
```

## License

仓库代码 license 待定；各数据源 license/terms 在 `manifest.json` 单独记录。  
不允许再分发的数据源不会被打包或生成外链卡。
