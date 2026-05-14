package index

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	// Use a real file in a temp dir — avoids connection-pool issues with
	// in-memory SQLite and WAL mode.
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestUpsertAndGet(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	page := Page{
		URL:        "https://docs.vulncheck.com/getting-started",
		Title:      "Getting Started",
		Breadcrumb: "Getting Started",
		Content:    "Welcome to VulnCheck.",
	}
	if err := db.Upsert(ctx, page, time.Now().Unix()); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := db.Get(ctx, page.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected page, got nil")
	}
	if got.Title != page.Title {
		t.Errorf("title: got %q, want %q", got.Title, page.Title)
	}
	if got.Content != page.Content {
		t.Errorf("content: got %q, want %q", got.Content, page.Content)
	}
	if got.Breadcrumb != page.Breadcrumb {
		t.Errorf("breadcrumb: got %q, want %q", got.Breadcrumb, page.Breadcrumb)
	}
}

func TestGetMissing(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	got, err := db.Get(ctx, "https://docs.vulncheck.com/does-not-exist")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestUpsertIdempotent(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	page := Page{
		URL:     "https://docs.vulncheck.com/api",
		Title:   "API v1",
		Content: "Old content.",
	}
	if err := db.Upsert(ctx, page, 1); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	page.Title = "API v2"
	page.Content = "New content."
	if err := db.Upsert(ctx, page, 2); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	got, err := db.Get(ctx, page.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Title != "API v2" {
		t.Errorf("title: got %q, want %q", got.Title, "API v2")
	}
	if got.Content != "New content." {
		t.Errorf("content: got %q, want %q", got.Content, "New content.")
	}

	var count int
	if err := db.conn.QueryRow("SELECT count(*) FROM pages").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("upsert created duplicate rows: got %d, want 1", count)
	}
}

func TestUpsertSyncsFTS(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	page := Page{
		URL:     "https://docs.vulncheck.com/api/auth",
		Title:   "Authentication",
		Content: "Bearer token required.",
	}
	if err := db.Upsert(ctx, page, time.Now().Unix()); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	results, err := db.Search(ctx, "bearer", 5)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) == 0 {
		t.Error("FTS index not synced after upsert: search returned no results")
	}
}

func TestSearch(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now().Unix()

	pages := []Page{
		{
			URL:        "https://docs.vulncheck.com/api/auth",
			Title:      "API Authentication",
			Breadcrumb: "API > Authentication",
			Content:    "Use a Bearer token to authenticate all requests.",
		},
		{
			URL:        "https://docs.vulncheck.com/getting-started",
			Title:      "Getting Started",
			Breadcrumb: "Getting Started",
			Content:    "Welcome to VulnCheck. Explore our products.",
		},
	}
	for _, p := range pages {
		if err := db.Upsert(ctx, p, now); err != nil {
			t.Fatalf("upsert %q: %v", p.URL, err)
		}
	}

	results, err := db.Search(ctx, "authentication", 5)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected results, got none")
	}
	if results[0].URL != "https://docs.vulncheck.com/api/auth" {
		t.Errorf("top result: got %q, want auth page", results[0].URL)
	}
}

func TestSearchEmpty(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	results, err := db.Search(ctx, "zzznoresultszzz", 5)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestSearchTitleRanksHigher(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now().Unix()

	// "rate limit" appears once in the body of page A but is the title of page B.
	// With BM25 weights title×10 > body×1, page B must rank first.
	pages := []Page{
		{
			URL:     "https://docs.vulncheck.com/api/overview",
			Title:   "API Overview",
			Content: "VulnCheck imposes a rate limit on all API calls.",
		},
		{
			URL:     "https://docs.vulncheck.com/api/rate-limits",
			Title:   "Rate Limits",
			Content: "Each API key is subject to the following constraints.",
		},
	}
	for _, p := range pages {
		if err := db.Upsert(ctx, p, now); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	results, err := db.Search(ctx, "rate limit", 5)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) < 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].URL != "https://docs.vulncheck.com/api/rate-limits" {
		t.Errorf("title-match should rank first, got %q", results[0].URL)
	}
}

func TestHasResearch(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	if db.HasResearch(ctx) {
		t.Error("empty db should not have research pages")
	}

	// Docs page should not count.
	if err := db.Upsert(ctx, Page{
		URL:     "https://docs.vulncheck.com/api",
		Title:   "API",
		Content: "some docs",
	}, time.Now().Unix()); err != nil {
		t.Fatalf("upsert docs: %v", err)
	}
	if db.HasResearch(ctx) {
		t.Error("docs-only db should not report HasResearch")
	}

	// Adding a research:// page flips the flag.
	if err := db.Upsert(ctx, Page{
		URL:     "research://initial-access/initial-access.ipynb",
		Title:   "Initial Access Intelligence",
		Content: "CVEs in IAI | 849",
	}, time.Now().Unix()); err != nil {
		t.Fatalf("upsert research: %v", err)
	}
	if !db.HasResearch(ctx) {
		t.Error("db with research:// page should report HasResearch")
	}
}

func TestSearchResearchIsolated(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now().Unix()

	// A docs page and a research page that both match "exploitation".
	if err := db.Upsert(ctx, Page{
		URL:     "https://docs.vulncheck.com/products/kev",
		Title:   "KEV",
		Content: "exploitation data from the KEV catalog",
	}, now); err != nil {
		t.Fatalf("upsert docs: %v", err)
	}
	if err := db.Upsert(ctx, Page{
		URL:        "research://known-exploited-vulnerabilities/2025-dashboard.ipynb",
		Title:      "2025 VulnCheck Known Exploited Vulnerabilities",
		Breadcrumb: "Research / Known Exploited Vulnerabilities",
		Content:    "exploitation timelines and KEV dashboard statistics for 2025",
	}, now); err != nil {
		t.Fatalf("upsert research: %v", err)
	}

	results, err := db.SearchResearch(ctx, "exploitation", 5)
	if err != nil {
		t.Fatalf("SearchResearch: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 research result, got %d", len(results))
	}
	if results[0].URL != "research://known-exploited-vulnerabilities/2025-dashboard.ipynb" {
		t.Errorf("wrong URL: got %q", results[0].URL)
	}

	// Verify search_docs still returns the docs page (not filtered out).
	docsResults, err := db.Search(ctx, "exploitation", 5)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(docsResults) == 0 {
		t.Error("Search should return both corpora, got none")
	}
	var foundDocs bool
	for _, r := range docsResults {
		if r.URL == "https://docs.vulncheck.com/products/kev" {
			foundDocs = true
		}
	}
	if !foundDocs {
		t.Error("docs page missing from Search results")
	}
}

func TestSearchResearchEmpty(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	results, err := db.SearchResearch(ctx, "zzznoresultszzz", 5)
	if err != nil {
		t.Fatalf("SearchResearch: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

// TestSearchMultiTokenOR verifies that a multi-word query returns results when
// each token appears in a different document (OR semantics). Under the old AND
// semantics both documents would have been silently excluded.
func TestSearchMultiTokenOR(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now().Unix()

	// Two research pages: each contains only one of the two query tokens.
	if err := db.Upsert(ctx, Page{
		URL:     "research://notebook/memory.ipynb",
		Title:   "Memory Management",
		Content: "strategies for memory allocation and garbage collection",
	}, now); err != nil {
		t.Fatalf("upsert memory page: %v", err)
	}
	if err := db.Upsert(ctx, Page{
		URL:     "research://notebook/leak.ipynb",
		Title:   "Resource Leaks",
		Content: "detecting and fixing resource leaks in long-running processes",
	}, now); err != nil {
		t.Fatalf("upsert leak page: %v", err)
	}

	results, err := db.SearchResearch(ctx, "memory leak", 5)
	if err != nil {
		t.Fatalf("SearchResearch: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected results for multi-token query with OR semantics, got none")
	}

	urls := make(map[string]bool, len(results))
	for _, r := range results {
		urls[r.URL] = true
	}
	if !urls["research://notebook/memory.ipynb"] {
		t.Error("memory.ipynb missing from results")
	}
	if !urls["research://notebook/leak.ipynb"] {
		t.Error("leak.ipynb missing from results")
	}
}

func TestSearchLimitRespected(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now().Unix()

	for i := 0; i < 10; i++ {
		p := Page{
			URL:     "https://docs.vulncheck.com/page/" + string(rune('a'+i)),
			Title:   "Authentication Guide",
			Content: "Authenticate with a token.",
		}
		if err := db.Upsert(ctx, p, now); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	results, err := db.Search(ctx, "authentication", 3)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) > 3 {
		t.Errorf("limit not respected: got %d results, want ≤3", len(results))
	}
}
