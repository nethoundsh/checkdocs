// Package vulncheck provides a client for the VulnCheck v3 REST API.
package vulncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	baseURL    = "https://api.vulncheck.com/v3"
	cacheTTL   = 10 * time.Minute
	maxRetries = 3
)

// Client is a thread-safe VulnCheck API client with response caching and
// exponential backoff on rate-limit and server errors.
type Client struct {
	token     string
	http      *http.Client
	cache     *responseCache
	available map[string]bool // populated lazily via /v3/index
	availMu   sync.RWMutex
	availOnce sync.Once
}

// NewClient constructs a Client. token is a VulnCheck Bearer token.
func NewClient(token string) *Client {
	return &Client{
		token: token,
		http:  &http.Client{Timeout: 15 * time.Second},
		cache: newResponseCache(),
	}
}

// AvailableIndices returns the set of index names the token has access to.
// The result is fetched once and cached for the lifetime of the Client.
func (c *Client) AvailableIndices(ctx context.Context) (map[string]bool, error) {
	var fetchErr error
	c.availOnce.Do(func() {
		data, err := c.get(ctx, baseURL+"/index", nil)
		if err != nil {
			fetchErr = err
			return
		}
		var resp struct {
			Data []struct {
				IndexName string `json:"index_name"`
			} `json:"data"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			fetchErr = fmt.Errorf("parse index list: %w", err)
			return
		}
		m := make(map[string]bool, len(resp.Data))
		for _, d := range resp.Data {
			m[d.IndexName] = true
		}
		c.availMu.Lock()
		c.available = m
		c.availMu.Unlock()
	})
	if fetchErr != nil {
		return nil, fetchErr
	}
	c.availMu.RLock()
	defer c.availMu.RUnlock()
	return c.available, nil
}

// HasIndex reports whether the token has access to the named index,
// fetching the index list on first call.
func (c *Client) HasIndex(ctx context.Context, name string) bool {
	m, err := c.AvailableIndices(ctx)
	if err != nil {
		return false
	}
	return m[name]
}

// QueryIndex queries a named index and returns the raw data entries as JSON
// objects. params may include "cve", "limit", "page", etc.
func (c *Client) QueryIndex(ctx context.Context, index string, params url.Values) ([]json.RawMessage, error) {
	u := baseURL + "/index/" + index
	data, err := c.get(ctx, u, params)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return resp.Data, nil
}

// DetectionRules fetches Suricata or Snort rules for a CVE from the
// initial-access rules endpoint. format must be "suricata" or "snort".
func (c *Client) DetectionRules(ctx context.Context, cve, format string) (string, error) {
	if format != "suricata" && format != "snort" {
		return "", fmt.Errorf("format must be 'suricata' or 'snort', got %q", format)
	}
	u := fmt.Sprintf("%s/rules/initial-access/%s", baseURL, format)
	params := url.Values{"cve": {cve}}
	data, err := c.get(ctx, u, params)
	if err != nil {
		return "", err
	}
	// Rules endpoint returns plain text wrapped in a JSON envelope.
	var resp struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		// Some rule responses are plain text directly.
		return string(data), nil
	}
	return resp.Data, nil
}

// get performs a cached, retried GET request. params are added as query
// string. Returns the raw response body on success.
func (c *Client) get(ctx context.Context, rawURL string, params url.Values) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if len(params) > 0 {
		u.RawQuery = params.Encode()
	}
	key := u.String()

	if cached := c.cache.get(key); cached != nil {
		return cached, nil
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			wait := time.Duration(1<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, key, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		switch resp.StatusCode {
		case http.StatusOK:
			c.cache.set(key, body)
			return body, nil
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("VulnCheck: invalid or expired token (401)")
		case http.StatusForbidden:
			return nil, fmt.Errorf("VulnCheck: index not available on your tier (403)")
		case http.StatusNotFound:
			return nil, fmt.Errorf("VulnCheck: not found (404)")
		case http.StatusTooManyRequests, http.StatusInternalServerError,
			http.StatusBadGateway, http.StatusServiceUnavailable:
			lastErr = fmt.Errorf("VulnCheck: status %d", resp.StatusCode)
			continue
		default:
			return nil, fmt.Errorf("VulnCheck: unexpected status %d", resp.StatusCode)
		}
	}
	return nil, fmt.Errorf("VulnCheck: max retries exceeded: %w", lastErr)
}

// responseCache is a simple in-memory cache with per-entry TTL.
type responseCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	data    []byte
	expires time.Time
}

func newResponseCache() *responseCache {
	return &responseCache{entries: make(map[string]cacheEntry)}
}

func (c *responseCache) get(key string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.expires) {
		delete(c.entries, key)
		return nil
	}
	return e.data
}

func (c *responseCache) set(key string, data []byte) {
	c.mu.Lock()
	c.entries[key] = cacheEntry{data: data, expires: time.Now().Add(cacheTTL)}
	c.mu.Unlock()
}
