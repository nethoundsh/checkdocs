package vulncheck

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// newTestClient creates a Client whose API calls go to handler instead of the
// real VulnCheck API. The test server is closed automatically when t finishes.
func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := NewClient("test-token")
	c.baseURL = srv.URL
	return c
}

func TestResponseCacheHitAndMiss(t *testing.T) {
	c := newResponseCache()

	if got := c.get("missing"); got != nil {
		t.Error("expected nil for missing key, got data")
	}

	c.set("key", []byte("hello"))
	if got := c.get("key"); string(got) != "hello" {
		t.Errorf("cache hit: got %q, want %q", got, "hello")
	}
}

func TestResponseCacheExpired(t *testing.T) {
	c := newResponseCache()
	// Inject an already-expired entry directly to avoid sleeping.
	c.mu.Lock()
	c.entries["key"] = cacheEntry{data: []byte("stale"), expires: time.Now().Add(-time.Second)}
	c.mu.Unlock()

	if got := c.get("key"); got != nil {
		t.Errorf("expected nil for expired entry, got %q", got)
	}
}

// TestClientHTTPErrors verifies that terminal HTTP errors are returned immediately
// without retry and carry the expected message text.
func TestClientHTTPErrors(t *testing.T) {
	cases := []struct {
		status  int
		wantErr string
	}{
		{http.StatusUnauthorized, "invalid or expired token"},
		{http.StatusPaymentRequired, "requires a paid plan"},
		{http.StatusForbidden, "not available on your tier"},
		{http.StatusNotFound, "not found"},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			_, err := c.QueryIndex(context.Background(), "test-index", nil)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestSearchCPE(t *testing.T) {
	payload := []map[string]any{
		{
			"cpe":  "cpe:2.3:o:opnsense:opnsense:*:*:*:*:*:*:*:*",
			"cves": []any{"CVE-2024-1234", "CVE-2024-5678"},
		},
	}
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search/cpe" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.URL.Query().Get("vendor") == "" {
			t.Error("expected vendor query param")
		}
		json.NewEncoder(w).Encode(map[string]any{"data": payload})
	}))

	results, err := c.SearchCPE(context.Background(), url.Values{"vendor": {"opnsense"}, "isVulnerable": {"true"}})
	if err != nil {
		t.Fatalf("SearchCPE: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	var got map[string]any
	if err := json.Unmarshal(results[0], &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if got["cpe"] != payload[0]["cpe"] {
		t.Errorf("cpe: got %q, want %q", got["cpe"], payload[0]["cpe"])
	}
}

// TestIdentify verifies that /v3/identify's top-level JSON array (not {"data":[...]})
// is parsed correctly.
func TestIdentify(t *testing.T) {
	payload := []map[string]any{
		{"identity": map[string]any{"vendor": "opnsense", "product": "opnsense"}},
	}
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identify" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		// /v3/identify returns a top-level array, unlike the other endpoints.
		json.NewEncoder(w).Encode(payload)
	}))

	results, err := c.Identify(context.Background(), "opnsense", "opnsense", "")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	var got map[string]any
	if err := json.Unmarshal(results[0], &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if identity, ok := got["identity"].(map[string]any); !ok || identity["vendor"] != "opnsense" {
		t.Errorf("identity.vendor: unexpected value in %v", got)
	}
}

// TestPURLLookup verifies that /v3/purl's {"data": {...}} envelope is unwrapped correctly.
func TestPURLLookup(t *testing.T) {
	const purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	payload := map[string]any{
		"cves": []any{"CVE-2021-44228"},
		"vulnerabilities": []any{
			map[string]any{"detection": "CVE-2021-44228", "fixed_version": "2.17.0"},
		},
	}
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/purl" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.URL.Query().Get("purl") != purl {
			t.Errorf("purl param: got %q, want %q", r.URL.Query().Get("purl"), purl)
		}
		json.NewEncoder(w).Encode(map[string]any{"data": payload})
	}))

	data, err := c.PURLLookup(context.Background(), purl)
	if err != nil {
		t.Fatalf("PURLLookup: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	cves, _ := got["cves"].([]any)
	if len(cves) != 1 || cves[0] != "CVE-2021-44228" {
		t.Errorf("cves: got %v, want [CVE-2021-44228]", cves)
	}
}

// TestAvailableIndices verifies that the index list is fetched once and cached:
// the mock server should be called exactly once even after multiple HasIndex calls.
func TestAvailableIndices(t *testing.T) {
	callCount := 0
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"name": "vulncheck-kev"}, {"name": "xdb"}},
		})
	}))

	if !c.HasIndex(context.Background(), "vulncheck-kev") {
		t.Error("vulncheck-kev should be available")
	}
	if !c.HasIndex(context.Background(), "xdb") {
		t.Error("xdb should be available")
	}
	if c.HasIndex(context.Background(), "ransomware") {
		t.Error("ransomware should not be available")
	}
	if callCount != 1 {
		t.Errorf("server called %d times, want 1 (cache should prevent re-fetches)", callCount)
	}
}
