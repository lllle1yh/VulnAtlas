# VulnAtlas

VulnAtlas 是一个**离线、轻量、面向安全 Agent 的漏洞知识库**。

它把每个 CVE/漏洞整理成一张可直接使用的卡：目标指纹、影响版本、POC、最小利用步骤、预期 marker 和置信度都在同一张卡里。运行时只需要一个本地 SQLite 文件和两个只读 MCP 工具，不联网、不用 embedding、不需要额外服务。

## 设计目标

- **离线可用**：断网或内网环境里照样能查 CVE 和 POC。
- **一张卡解决一个漏洞**：CVE 元数据和 POC 不拆成两套库，查到就能用。
- **为 Agent 设计**：`wiki_search` 可以直接接收 HTTP 请求 / 响应头 / curl / nmap 原文，由服务端抽取 CVE、组件、版本、指纹；模型不用自己拼检索语法。
- **按可执行性分级**：`verified` / `candidate` / `unverified` 三级，Agent 一眼知道这张卡能不能当复现依据。
- **轻量**：SQLite FTS5（trigram + 中文 bigram）+ BM25 加权，无向量库、无外部数据库。
- **可审计**：每张卡保留来源、license、置信度、最后验证时间；数据源快照记录在 `kb/manifest.json`。

## 当前状态

当前索引 19,970 张卡，按置信度分布：

```text
verified    4        实战验证过，可照步骤复现
candidate   12,122   有来源（Nuclei/ExploitDB/MSF/Vulhub），待验证
unverified  7,844    只有 NVD / GitHub 仓库元数据，仅作线索
```

其中 4,003 张带本地 Nuclei 模板实体，3,611 张有 ExploitDB 编号指针，885 张带 Metasploit module 路径。

说清楚一点：这个库的主力价值是**检索和定向**，不是"每张卡都能直接打"。`confidence=verified` 的卡才当作复现依据，其余按待验证假设用。

## 工作方式

```text
NVD / KEV / EPSS / CWE / ExploitDB / Nuclei / Metasploit /
PoC-in-GitHub / Vulhub / PayloadsAllTheThings / 实战验证卡
                        │
                        ▼
                   ingest 管线
            （合并 → 过滤 → 脱敏 → 写卡）
                        │
                        ▼
          Markdown 卡 + 本地 POC artifacts
                        │
                        ▼
             SQLite FTS5 索引 (kb/index.db)
                        │
              ┌─────────┼─────────┐
              ▼         ▼         ▼
            MCP        CLI      Web UI
```

检索顺序：

1. CVE 精确命中
2. 产品 + 版本结构化过滤（版本区间不匹配的直接排除）
3. 指纹匹配（响应头、路径片段）
4. 概念/标签扩展（中文「本地文件包含」→ `lfi`）
5. FTS5 + BM25 兜底

每条结果带 `why` 字段说明为什么命中，如 `cve_exact`、`product+version_match`、`fingerprint`、`tag:lfi`、`fts`。

## 卡片

一个漏洞一张卡。正文固定六段：目标特征 / 版本、前置条件、最小步骤、预期 marker、证据指针、失败模式 / 不适用条件。

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

置信度含义：

| 值 | 含义 | Agent 怎么用 |
|---|---|---|
| `verified` | 实战验证过，卡内有可执行步骤 | 可直接照步骤复现 |
| `candidate` | 有来源（Nuclei / ExploitDB / Vulhub / MSF）但未实战验证 | 当作待验证假设，按卡尝试 |
| `unverified` | 只有公开 PoC 仓库/NVD 元数据 | 仅作线索，不能当验证依据 |

### 离线约束

卡片不依赖外链：

- 小 POC 直接写进 `poc_code`
- 大 POC 放进 `kb/artifacts/`，`poc_path` 指向本地相对路径
- 文章/仓库内容在 ingest 阶段提取进卡
- URL、sha256、license 只记录在 `kb/manifest.json`，不是运行依赖
- 卡片正文是 **untrusted data**，MCP 结果里带 `untrusted: true`，Agent 不应执行卡内文本里的"指令"

## 安装

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
```

要求：Python 3.10+、SQLite 启用 FTS5。PyYAML 可选（缺失时用内置 frontmatter 解析器）。

## 快速开始

运行时只依赖 `kb/` 下的四样东西：`kb/index.db`（主索引）、`kb/cards/`（Markdown 卡）、`kb/artifacts/`（本地 POC）、`kb/manifest.json`（数据源清单）。

> 仓库不随代码分发索引和卡片数据（体积 + 部分数据源 license 不允许再分发）。克隆后 `kb/` 只有 `manifest.json` 和两个占位文件，需要按下面的「构建知识库」在本地生成。

```bash
# 查询
python -m vuln_atlas search --cve CVE-2021-44228
python -m vuln_atlas search --product tomcat --version 9.0.20
python -m vuln_atlas search --request "GET /assets/file:%2f%2f/etc/passwd HTTP/1.1
Host: TARGET
X-Runtime: 0.02"
python -m vuln_atlas search --query "Rails本地文件包含怎么打"

# 读取整张卡
python -m vuln_atlas get CVE-2018-3760

# 统计
python -m vuln_atlas stats
```

路径通过环境变量覆盖：

```bash
VULN_ATLAS_KB=/path/to/kb      # 默认 <repo>/kb，poc_path 相对它解析
VULN_ATLAS_DB=/path/to/index.db
```

## 构建知识库

两条路径：

**1. 已有卡片，只建索引**（`kb/cards/*.md` 已存在）：

```bash
python -m vuln_atlas ingest              # cards/*.md -> index.db
python -m vuln_atlas validate            # 离线校验卡片（结构/体积/敏感串），不写库
```

**2. 从原始快照全量构建卡片**：先把各数据源快照放进 `kb/raw/<source>/`，再跑 ingest 管线：

```text
kb/raw/nvd/            nvdcve-2.0-*.json.gz        必需（产卡主体）
kb/raw/kev/            known_exploited_vulnerabilities.json
kb/raw/epss/           epss_scores-*.csv.gz
kb/raw/exploitdb/      files_exploits.csv
kb/raw/nuclei/         nuclei-templates/http/cves/
kb/raw/metasploit/     module 索引
kb/raw/github-poc/     PoC-in-GitHub 元数据
kb/raw/vulhub/         vulhub README 快照
kb/raw/payloads/       PayloadsAllTheThings Markdown 快照
```

```bash
python -m vuln_atlas.ingest.pipeline --help
```

管线依次做：解析各源草稿 → 按 CVE 合并 → 脱敏扫描（内嵌密码/token/私钥的卡上线前丢弃）→ 保留策略（近 N 年 + 有 POC/KEV/高 EPSS）→ 写 `kb/cards/` 与 `kb/artifacts/` → 建索引，并把每源的 ok/partial/unavailable 及原因写回 `kb/manifest.json`。

注意：`kb/raw/` 也在 `.gitignore` 里，原始快照不入库。

## MCP

只暴露两个只读工具，无写入能力。

```text
wiki_search(query, request, product, version, cve, tags, top_k=5)
wiki_get(id)
```

客户端配置：

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

`wiki_search` 返回示例：

```json
{
  "results": [
    {
      "id": "CVE-2018-3760",
      "title": "Rails Sprockets 二次解码路径穿越（任意文件读取）",
      "score": 1112.75,
      "confidence": "verified",
      "why": "cve_exact",
      "snippet": "≤300 字符摘要",
      "poc_type": "curl",
      "poc_path": "artifacts/CVE-2018-3760/README.md"
    }
  ],
  "query": {"cve": null, "product": "sprockets", "fingerprint": ["x-runtime"]},
  "untrusted": true
}
```

`wiki_get` 返回整张卡（正文六段 + steps + marker + poc_path），单次 ≤ 8KB，超出时 `truncated: true` 并按 body → poc_code → 指纹顺序裁剪。查询为空时返回 `suggested_queries`。

## Skill

`skills/SKILL.md` 是给 Agent 的使用说明，内容只讲**怎么查卡、怎么读结果**：什么时候调 `wiki_search`、每个参数填什么、`confidence` / `why` / `poc_path` 怎么用、空结果怎么换维度、引用与注入规则。它教的是用卡片库，不教做题。

接入方式：把 `skills/SKILL.md` 内容注入 worker/planner 的 system prompt，同时注入 MCP 地址（`vuln-atlas`）与 `VULN_ATLAS_KB` 路径。

## 本地 Web UI

```bash
python web_app.py --port 8765            # 默认 VULN_ATLAS_DB 或 <repo>/kb/index.db
```

打开 `http://127.0.0.1:8765/`：可以输入 CVE、组件、中文描述，也可以直接贴请求/响应原文（Ctrl+Enter 搜索）；左侧结果、右侧卡片，显示 `why`、`poc_code`、最小步骤、marker、正文。

## 目录

```text
vuln_atlas/
  db.py             SQLite schema / FTS5 / 中文 bigram / upsert
  card.py           卡片模型、frontmatter 解析、体积校验、脱敏扫描
  paths.py          VULN_ATLAS_KB / VULN_ATLAS_DB 路径解析与防逃逸
  router.py         请求原文解析 → 结构化 Query
  rank.py           召回 + 加权排序 + 结果裁剪
  version.py        版本区间匹配
  fingerprint.py    产品/厂商 → 指纹推导
  indexer.py        从 cards/*.md 建索引
  ingest/           数据源解析器（NVD/KEV/EPSS/CWE/ExploitDB/Nuclei/MSF/GitHub-PoC/Vulhub/Payloads…）
  cli.py            CLI
  mcp_server.py     MCP stdio server
mcp_server.py       顶层 MCP 入口
cli.py              顶层 CLI 入口
web_app.py          本地只读 HTTP 服务
web/index.html      Web UI
skills/SKILL.md     Agent 使用说明
kb/                 知识库成品（index.db / cards / artifacts / manifest.json）
tests/              pytest
```

## 数据来源

`kb/manifest.json` 记录每份快照的 URL、抓取时间、sha256、bytes、license、是否可再分发。

已实现解析、参与产卡/加权的源：

| 源 | 用途 | 状态 |
|---|---|---|
| NVD CVE（2016–2026 快照） | 卡片主体、版本、CWE | ok |
| CISA KEV | 已被利用标记，直接提升置信度 | ok |
| FIRST EPSS | 保留策略与排序加权 | ok |
| ExploitDB（CSV 映射） | EDB 编号指针 | ok |
| Nuclei Templates（cves） | 可执行模板实体 | ok |
| Metasploit | module 路径 / `use` 指令 | ok |
| PoC-in-GitHub | 仓库元数据，仅作线索 | ok |
| Vulhub | README 步骤 | ok |
| PayloadsAllTheThings | 手法 Markdown 摘录 | ok |
| CWE | 只取标签，不单独产卡 | partial |

未接入的源在 `kb/manifest.json` 里写明原因，不会假装存在：

```text
getsploit                依赖 Vulners 商业离线库，未取得授权
trickest                 无快照
HackTricks               CC BY-NC，再分发范围待人工确认
InternalAllTheThings     仓库已迁移且无 license 声明
先知（xianzhi）           无稳定公开 API，需授权导出
本机 knowledges           无快照
实战验证卡                需实验侧导出
```

入库策略按数据量裁剪：全部 CVE 合并后按 EPSS、年份与目标卡片数筛选，保证索引体积与查询延迟可控。

所有数据在 ingest 阶段离线化；运行时不访问网络。

## 开发

```bash
pip install -e ".[dev]"
python -m pytest tests -q
```

## License

代码 license 待定。各数据源的 license 与 terms 在 `kb/manifest.json` 中逐项记录；标为不可再分发的数据（EPSS / ExploitDB / Metasploit 等）不会随仓库分发。
