# VulnAtlas

VulnAtlas 是一个**离线、轻量、面向安全 Agent 的漏洞知识库**。

它把每个 CVE/漏洞整理成一张可直接使用的卡：目标指纹、影响版本、POC、最小利用步骤、预期 marker 和验证状态都在同一张卡里。运行时只需要一个 SQLite 文件和两个 MCP 工具，不依赖联网、不依赖向量数据库，也不需要额外服务。

## 设计目标

- **离线可用**：比赛或内网环境无法访问外网时，仍能查询 CVE 和 POC。
- **一张卡解决一个漏洞**：CVE 元数据和 POC 不拆成两套库，Agent 查到就能用。
- **为 Agent 设计**：返回结构化、小体积结果，不让模型在长文和链接里翻找。
- **轻量**：SQLite FTS5 + BM25，不引入 embedding、向量库或外部数据库。
- **可审计**：每张卡保留来源、置信度和最后验证时间。

## 工作方式

```text
NVD / KEV / EPSS / ExploitDB / Nuclei / Metasploit /
GitHub PoC / Vulhub / 技术文章 / 实战验证卡
                    │
                    ▼
               ingest 管线
                    │
                    ▼
   Markdown 卡片 + 本地 POC artifacts
                    │
                    ▼
          SQLite FTS5 索引 (index.db)
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
       CLI 查询            MCP 查询
```

运行时查询顺序：

1. CVE 精确匹配
2. 产品 + 版本过滤
3. 路径、响应头、指纹匹配
4. 概念/别名扩展
5. FTS5 + BM25 兜底

## 卡片

一个漏洞一张卡，POC 直接放在卡内或本地 `artifacts/` 中。

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
poc_path: artifacts/CVE-2018-3760/README.md
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

正文包含：

- 目标特征 / 版本
- 前置条件
- 最小步骤
- 预期 marker
- 证据指针
- 失败模式

### 离线约束

卡片不依赖外链：

- 小 POC 直接写入 `poc_code`
- 大 POC 放到本地 `artifacts/`，`poc_path` 指向本地文件
- 文章和仓库内容在 ingest 时提取到卡内
- URL、license、sha256 等只记录在数据清单中，不作为运行依赖

## 安装

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

要求：

- Python 3.10+
- SQLite 启用 FTS5
- PyYAML

## 快速开始

初始化索引：

```bash
python -m vuln_atlas.cli --db index.db init
```

导入 Nuclei 模板：

```bash
python -m vuln_atlas.cli --db index.db ingest-nuclei --root raw/nuclei-templates
```

查询：

```bash
python -m vuln_atlas.cli --db index.db search "RubyonRails本地文件包含怎么打" --top-k 5
```

读取一张卡：

```bash
python -m vuln_atlas.cli --db index.db get CVE-2018-3760
```

## MCP

服务只暴露两个只读工具：

```text
wiki_search(query, request, product, version, cve, tags, top_k)
wiki_get(id)
```

启动：

```bash
python -m vuln_atlas.mcp_server
```

环境变量：

```bash
VULN_ATLAS_DB=/path/to/index.db
```

返回结果包含：

```json
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
```

`wiki_get` 返回卡片正文，最多 8KB；POC 文件只返回本地路径。

## 本地 Web UI

```bash
python web_app.py --db index.db --port 8765
```

打开 `http://127.0.0.1:8765/`，可以输入 CVE、组件、报错或自然语言查询，点击结果查看卡片。

## 目录

```text
vuln_atlas/
  db.py               SQLite schema / FTS5
  search.py           查询归一化 / 路由 / 排序
  ingest/             数据源解析器
  cli.py              CLI
  mcp_server.py       MCP stdio server
web_app.py            本地 HTTP 服务
web/index.html        Web UI
cards/                Markdown 卡片
artifacts/            本地 POC
raw/                  数据源快照
tests/
```

## 数据来源

支持接入：

- NVD CVE、CISA KEV、FIRST EPSS、CWE
- ExploitDB、Nuclei Templates、Metasploit、getsploit
- PoC-in-GitHub、trickest/cve、Vulhub
- HackTricks、PayloadsAllTheThings、InternalAllTheThings
- 授权整理的中文技术文章
- 实战验证卡

所有数据在 ingest 阶段离线化；运行时不访问网络。

## 开发

```bash
python -m pytest tests -q
```

## License

代码 license 待定。各数据源的 license 和 terms 在数据清单中单独记录；不允许再分发的内容不会被纳入卡片。
