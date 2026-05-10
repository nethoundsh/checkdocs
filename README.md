# vulncheck-docs-agent

Agentic Q&A over [VulnCheck](https://docs.vulncheck.com) documentation. Built as a portfolio project demonstrating tool-using LLMs over a scraped, locally-indexed knowledge base.

## Architecture

- **Scraper** (`cmd/scraper`): one-shot crawler, HTML → markdown, persisted to SQLite with FTS5.
- **Server** (`cmd/server`): HTTP API + minimal frontend. Agent loop with two tools (`search_docs`, `fetch_page`) backed by SQLite full-text search.
- **Models**: any chat model via OpenRouter; users bring their own API key.

## Status

In development.
