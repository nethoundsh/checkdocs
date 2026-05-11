# checkdocs

> Agentic Q&A over the [VulnCheck](https://docs.vulncheck.com) documentation and live intelligence API — a BM25-indexed, locally-served assistant built in Go.

Built in Go. Requires an OpenRouter API key; a VulnCheck API token unlocks live intelligence queries.

---

## What it does

`checkdocs` scrapes the full VulnCheck documentation, indexes it locally with SQLite FTS5, and wraps it in a tool-using LLM agent. Ask a natural-language question about VulnCheck's APIs, data endpoints, authentication, or intelligence products; the agent searches and reads the relevant docs pages and returns a cited answer grounded in retrieved content.

With a VulnCheck API token, the agent gains four additional live-data tools that query `api.vulncheck.com/v3/` directly:

| Tool | What it answers |
|---|---|
| `kev_lookup` | Is this CVE in the KEV catalog? When was it added? Is it linked to ransomware campaigns? |
| `cve_exploits` | What botnets, ransomware families, or threat actors exploit this CVE? (queries available indices concurrently) |
| `detection_rules` | Give me Suricata or Snort rules for this CVE |
| `vulncheck_query` | Escape hatch — query any index by name with arbitrary parameters |

Without a VulnCheck token the tool surface is docs-only; the live tools are silently omitted from the agent's tool list.

Two interfaces ship: a **CLI** for quick lookups from the terminal and an **HTTP server** with a browser-based chat UI for longer research sessions.

```
$ go run ./cmd/agent "What endpoints are available for Initial Access Intelligence?"

→ search_docs({"query": "initial access intelligence endpoints"})
  ✓ search_docs: 5 pages

→ fetch_page({"url": "https://docs.vulncheck.com/products/initial-access-intelligence"})
  ✓ fetch_page: Initial Access Intelligence (4821 bytes)

VulnCheck's Initial Access Intelligence product exposes the following endpoints:

- **`/v3/backup/initial-access`** — bulk JSONL download of the full dataset
- **`/v3/index/initial-access`** — paginated, filterable index query

Both require a Bearer token. The bulk endpoint is rate-limited to one concurrent
download per API key. Source: [Initial Access Intelligence](https://docs.vulncheck.com/products/initial-access-intelligence)
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  docs.vulncheck.com/llms.txt  (machine-readable manifest)   │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTP GET (102 pages, En locale)
                        ▼
┌───────────────────────────────────┐
│  cmd/scraper                      │
│  ─────────────────────────────── │
│  • Parses llms.txt manifest       │
│  • Fetches /raw/*.md for each     │
│    page (polite 1-second delay)   │
│  • Derives human-readable URLs    │
│  • Generates breadcrumb hierarchy │
│  • Upserts into SQLite (WAL mode) │
└───────────────────────┬───────────┘
                        │ writes
                        ▼
┌───────────────────────────────────┐
│  data/docs.db  (SQLite + FTS5)    │
│  ─────────────────────────────── │
│  pages table   ← base storage     │
│  pages_fts     ← virtual FTS5     │
│    BM25 weights:                  │
│      title      × 10.0            │
│      breadcrumb ×  5.0            │
│      body       ×  1.0            │
│  Porter stemmer + unicode61        │
└─────────┬─────────────────────────┘
          │ reads (concurrent, WAL)
          ▼
┌─────────────────────────────────────────────────────────────┐
│  internal/agent  (tool-using LLM loop)                      │
│  ─────────────────────────────────────────────────────────  │
│  Doc tools (always):                                         │
│    search_docs(query, limit)  →  BM25 results + snippets    │
│    fetch_page(url)            →  full markdown content       │
│                                                              │
│  Live tools (when VulnCheck token present):                  │
│    kev_lookup      cve_exploits                              │
│    detection_rules vulncheck_query                           │
│          │                                                   │
│          └── internal/vulncheck  ─────────────────────────┐ │
│               • 10-min response cache                      │ │
│               • exponential backoff (429 / 5xx)            │ │
│               • tier-aware index discovery                 │ │
│               └──────────────────────────────────────────►─┤ │
│                              api.vulncheck.com/v3/         │ │
│  Loop:  system prompt → user question → [tool call →        │
│         tool result]* → streamed answer  (max 16 iterations)│
│                                                              │
│  Session: message history persisted per UUID, 30-min TTL    │
│  Backend: OpenRouter (OpenAI-compatible API)                 │
│  Default model: anthropic/claude-sonnet-4.5                  │
└───────┬─────────────────┬───────────────────────────────────┘
        │                 │
        ▼                 ▼
┌───────────────┐  ┌──────────────────────────────────────────┐
│  cmd/agent    │  │  cmd/server                              │
│  ─────────── │  │  ──────────────────────────────────────  │
│  CLI — reads  │  │  HTTP server on :8080                    │
│  events and   │  │  POST /api/chat  → SSE event stream      │
│  renders ANSI │  │  GET  /          → embedded web UI       │
│  to stdout    │  │                                          │
└───────────────┘  │  BYOK: X-OpenRouter-Key (required)       │
                   │        X-VulnCheck-Token (optional)      │
                   │  per-request, never stored or logged     │
                   └──────────────────────────────────────────┘
```

---

## Key design decisions

### 1. llms.txt as the discovery mechanism

Rather than writing a custom crawler, the scraper bootstraps entirely from VulnCheck's own machine-readable manifest at `https://docs.vulncheck.com/llms.txt`. This file lists every doc page with its title, raw markdown URL, and a one-line description — all the metadata needed to build the index without any HTML parsing. The approach is zero-config, adapts automatically to new documentation sections, and respects the intent behind the format.

### 2. BM25 ranking tuned for documentation search

The FTS5 virtual table uses Porter stemming with explicit BM25 column weights:

```sql
ORDER BY bm25(pages_fts, 10.0, 5.0, 1.0)
--                        ^      ^    ^
--                        title  bc   body
```

Title matches rank 10× over body content and breadcrumb matches rank 5×. For documentation search — where "rate limit" in a page title is far more signal than "rate limit" appearing once in prose — this produces meaningfully better results than unweighted full-text search.

### 3. SSE streaming with typed event channels

The agent emits structured events over a Go channel (`tool_call`, `tool_result`, `token`, `done`, `error`). The server serializes these as Server-Sent Events with a typed `event:` field, which lets the browser use `addEventListener` per type rather than branching inside a single `onmessage` handler. The result: tool calls and their results render in real time alongside streaming answer tokens, giving the user a live view into what the agent is doing.

No `WriteTimeout` is set on the HTTP server — SSE responses are long-lived by design. The `X-Accel-Buffering: no` header disables proxy buffering for nginx/Cloudflare deployments.

### 4. BYOK — the server never touches your API key

The OpenRouter API key is passed by the browser as an `X-OpenRouter-Key` request header and flows directly into the agent constructor for that request. It is never logged, never stored in a session, and exits scope when the handler returns. The same pattern applies to the optional `X-VulnCheck-Token` — a fresh `vulncheck.Client` is constructed per request and discarded when the handler returns. The server-side log line for a chat request records only model name and question length:

```
level=INFO msg=chat model=anthropic/claude-sonnet-4.5 q_len=47
```

### 5. VulnCheck API tools — named tools for the 80% case, escape hatch for the rest

Four live-data tools extend the agent when a VulnCheck API token is present. The design follows a hybrid pattern: named, purpose-built tools (`kev_lookup`, `cve_exploits`, `detection_rules`) cover the most common intelligence queries with clean, constrained inputs; `vulncheck_query` serves as an escape hatch for anything not covered, accepting an arbitrary index name and parameters.

The tools omit themselves gracefully — `internal/vulncheck.Client.HasIndex()` checks the authenticated token's available indices via a lazy GET `/v3/index` call (cached for the session lifetime). `cve_exploits` queries whichever of `initial-access`, `botnets`, `ransomware`, and `threat-actors` the token can reach, concurrently, using a `sync.WaitGroup`. Tier restrictions surface as explicit error messages ("not available on your tier") rather than silent empty results, so the model can explain the limitation rather than hallucinating data.

---

## Prerequisites

- **Go 1.21+** (the module targets `go 1.26.3` — any recent toolchain works)
- An **[OpenRouter](https://openrouter.ai) API key** (`sk-or-v1-…`)
- An optional **[VulnCheck](https://vulncheck.com) API token** — enables live intelligence tools (`kev_lookup`, `cve_exploits`, `detection_rules`, `vulncheck_query`); without it the agent is docs-only
- No cgo or system SQLite installation required — `modernc.org/sqlite` is a pure Go SQLite implementation compiled directly into the binary
- The web UI fetches two CDN assets at runtime: Montserrat from Google Fonts and `marked.js` from jsDelivr (for markdown rendering). The CLI has no such dependency.

---

## Quick start

### 1. Clone and build

```bash
git clone https://github.com/nethoundsh/checkdocs
cd checkdocs
```

### 2. Scrape and index the VulnCheck docs

```bash
go run ./cmd/scraper
# Fetches docs.vulncheck.com/llms.txt, downloads 102 pages, writes data/docs.db
# Takes ~2 minutes at the default 1-second politeness delay.
```

### 3a. Run the CLI agent

```bash
export OPENROUTER_API_KEY=sk-or-v1-...
# Or create a .env file: echo "OPENROUTER_API_KEY=sk-or-v1-..." > .env

go run ./cmd/agent "How does VulnCheck handle API authentication?"
```

### 3b. Run the web server

```bash
go run ./cmd/server
# Listening on :8080

open http://localhost:8080
# Enter your OpenRouter key in the header input, then ask questions.
```

---

## CLI usage

```
Usage: agent [-model M] [-db PATH] "<question>"

Flags:
  -db      path to SQLite database (default: data/docs.db)
  -model   OpenRouter model identifier (default: anthropic/claude-sonnet-4.5)

Environment:
  OPENROUTER_API_KEY     required; loaded from .env if present
  VULNCHECK_API_TOKEN    optional; enables live VulnCheck API tools; loaded from .env if present
```

The CLI renders tool activity in color to stderr (cyan for calls, green for results) and streams the final answer to stdout — pipe-friendly.

```bash
# Use a different model
go run ./cmd/agent -model google/gemini-2.5-pro "What is EPSS scoring?"

# Redirect answer to a file
go run ./cmd/agent "Summarize the Exploit Intelligence product" > summary.md
```

---

## Server usage

```
Usage: server [-addr ADDR] [-db PATH] [-model MODEL]

Flags:
  -addr    listen address (default: :8080)
  -db      path to SQLite database (default: data/docs.db)
  -model   default OpenRouter model (default: anthropic/claude-sonnet-4.5)
```

### API

```
POST /api/chat
Headers:
  Content-Type: application/json
  X-OpenRouter-Key: sk-or-v1-...
  X-VulnCheck-Token: <token> (optional — enables live intelligence tools)

Body:
  { "question": "string", "model": "string (optional)", "session_id": "string (optional)" }

Response: text/event-stream
```

SSE event types:

| Event | Payload fields | Description |
|---|---|---|
| `session` | `Content` | Session UUID — capture this and send as `session_id` on subsequent requests to continue the conversation |
| `tool_call` | `Name`, `Args` | Agent is about to call a tool |
| `tool_result` | `Name`, `Result` | Tool returned; human-readable summary |
| `token` | `Content` | Streamed answer token |
| `done` | — | Answer complete |
| `error` | `Content` | Agent or stream error |

---

## Re-indexing the docs

The scraper is idempotent — re-running it upserts changed pages and leaves the database in a consistent state:

```bash
go run ./cmd/scraper

# Custom delay (default 1s, increase to be more polite)
go run ./cmd/scraper -delay 2s

# Custom database path
go run ./cmd/scraper -db /var/data/vulncheck-docs.db
```

The index automatically stays in sync via SQLite triggers: insert/update/delete on the `pages` table propagates to the `pages_fts` virtual table without any application-layer bookkeeping.

---

## Supported models

The server and CLI accept any model available on OpenRouter. Models in the web UI dropdown:

| Model | Notes |
|---|---|
| `anthropic/claude-sonnet-4.5` | Default. Best balance of speed and answer quality. |
| `anthropic/claude-opus-4.6` | Highest quality; slower and more expensive. |
| `google/gemini-2.5-pro` | Strong alternative; good at structured doc synthesis. |
| `google/gemini-2.5-flash` | Fast and cheap for simple lookups. |
| `openai/gpt-4o-mini` | Lightweight option. |

Any `openai`-compatible model slug from OpenRouter can be passed via `-model` on the CLI.

---

## Testing

```bash
go test ./...
```

16 tests across three packages, no external dependencies required:

| Package | Tests | What's covered |
|---|---|---|
| `cmd/scraper` | 3 | `deriveHumanURL`, `breadcrumbFromURL`, `titleCase` — pure URL and string transforms |
| `internal/index` | 8 | Upsert + get roundtrip, missing-URL nil return, upsert idempotency, FTS trigger sync, basic search, empty search, BM25 title-ranking, limit enforcement |
| `cmd/server` | 5 | SSE wire format (`writeSSE`), all four HTTP validation paths in `chatHandler` (missing key → 401, bad JSON → 400, empty question → 400, over-length → 400), and the 8000-char boundary |

The `internal/index` tests run against a real SQLite file in a temp directory — no mocking, no in-memory shortcuts — so the FTS triggers and BM25 ranking weights are exercised exactly as they run in production.

---

## Project structure

```
checkdocs/
├── cmd/
│   ├── agent/        # CLI entrypoint
│   ├── scraper/      # One-shot doc crawler
│   └── server/       # HTTP API + embedded web UI
│       └── web/      # index.html (embedded at build time)
├── internal/
│   ├── agent/        # Tool-using LLM loop, event types
│   ├── index/        # SQLite open/migrate/search/upsert
│   └── vulncheck/    # VulnCheck v3 API client, response cache, retry
├── data/             # docs.db lives here (gitignored)
└── go.mod
```

---

## Roadmap

- [x] Adapt UI to VulnCheck brand colors and visual identity
- [x] Multi-turn conversation memory with 30-minute session TTL and "New chat" reset
- [x] Live VulnCheck API tools (`kev_lookup`, `cve_exploits`, `detection_rules`, `vulncheck_query`)
- [x] Test suite for the index, scraper, and server layers
- [ ] Semantic/hybrid search (BM25 + embeddings) for better recall on paraphrase queries
- [ ] Automatic re-indexing on a schedule (cron or webhook trigger from docs deploys)
- [ ] Public deployment with rate limiting and key sandboxing

---

## Built by

**[@nethoundsh](https://github.com/nethoundsh)** — solo project, built in a few days. Open source and under active development.
