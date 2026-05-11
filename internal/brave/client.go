// Package brave provides a client for the Brave Web Search API.
package brave

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const apiURL = "https://api.search.brave.com/res/v1/web/search"

// Client is a Brave Web Search API client.
type Client struct {
	apiKey string
	http   *http.Client
}

// Result is a single web search result.
type Result struct {
	Title       string
	URL         string
	Description string
}

// NewClient constructs a Client. apiKey is a Brave Search subscription token.
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		http:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Search queries the Brave Web Search API and returns up to count results.
func (c *Client) Search(ctx context.Context, query string, count int) ([]Result, error) {
	if count <= 0 || count > 20 {
		count = 5
	}
	u := apiURL + "?" + url.Values{
		"q":     {query},
		"count": {fmt.Sprintf("%d", count)},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Subscription-Token", c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("brave search: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("brave search: invalid API key (401)")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("brave search: rate limited (429) — free tier allows 2000 queries/month")
	default:
		return nil, fmt.Errorf("brave search: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("brave search: read body: %w", err)
	}

	var apiResp struct {
		Web struct {
			Results []struct {
				Title       string `json:"title"`
				URL         string `json:"url"`
				Description string `json:"description"`
			} `json:"results"`
		} `json:"web"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("brave search: parse response: %w", err)
	}

	results := make([]Result, 0, len(apiResp.Web.Results))
	for _, r := range apiResp.Web.Results {
		results = append(results, Result{
			Title:       r.Title,
			URL:         r.URL,
			Description: r.Description,
		})
	}
	return results, nil
}
