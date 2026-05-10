package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/nethoundsh/checkdocs/internal/index"
)

const (
	manifestURL = "https://docs.vulncheck.com/llms.txt"
	userAgent   = "checkdocs/0.1 (+https://github.com/nethoundsh/checkdocs)"
	targetLocale = "En"
)

// linkRE matches markdown list items of the form:
//   - [Title](https://docs.vulncheck.com/raw/path.md): description
var linkRE = regexp.MustCompile(`^\s*-\s*\[([^\]]+)\]\(([^)]+)\)\s*:\s*(.+?)\s*$`)

type manifestEntry struct {
	Title       string
	URL         string
	Description string
}

func main() {
	dbPath := flag.String("db", "data/docs.db", "path to SQLite database")
	delay := flag.Duration("delay", time.Second, "delay between page fetches")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := context.Background()

	if err := os.MkdirAll("data", 0o755); err != nil {
		logger.Error("create data dir", "err", err)
		os.Exit(1)
	}

	db, err := index.Open(*dbPath)
	if err != nil {
		logger.Error("open db", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	client := &http.Client{Timeout: 30 * time.Second}

	logger.Info("fetching manifest", "url", manifestURL)
	entries, err := fetchManifest(ctx, client, manifestURL, targetLocale)
	if err != nil {
		logger.Error("fetch manifest", "err", err)
		os.Exit(1)
	}
	logger.Info("manifest parsed", "pages", len(entries))

	now := time.Now().Unix()
	var ok, fail int
	for i, e := range entries {
		page, err := fetchPage(ctx, client, e)
		if err != nil {
			logger.Warn("fetch failed", "url", e.URL, "err", err)
			fail++
			continue
		}
		if err := db.Upsert(ctx, *page, now); err != nil {
			logger.Warn("upsert failed", "url", e.URL, "err", err)
			fail++
			continue
		}
		ok++
		logger.Info("stored", "n", i+1, "total", len(entries), "title", page.Title)
		time.Sleep(*delay)
	}

	logger.Info("done", "ok", ok, "failed", fail)
}

// fetchManifest downloads llms.txt and returns entries for the requested locale.
func fetchManifest(ctx context.Context, c *http.Client, url, locale string) ([]manifestEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest: status %d", resp.StatusCode)
	}

	var (
		entries     []manifestEntry
		currentLoc  string
		wantHeading = "## " + locale
	)
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20) // some lines are long

	for scanner.Scan() {
		line := scanner.Text()
		// Track current locale section.
		if strings.HasPrefix(line, "## ") {
			currentLoc = strings.TrimSpace(line)
			continue
		}
		if currentLoc != wantHeading {
			continue
		}
		m := linkRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		entries = append(entries, manifestEntry{
			Title:       strings.TrimSpace(m[1]),
			URL:         strings.TrimSpace(m[2]),
			Description: strings.TrimSpace(m[3]),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// fetchPage downloads the markdown content for one manifest entry.
func fetchPage(ctx context.Context, c *http.Client, e manifestEntry) (*index.Page, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// The /raw/path.md URL is what users will share/reference in answers,
	// but the human-readable URL is the same path without /raw/ and without .md.
	publicURL := deriveHumanURL(e.URL)
	return &index.Page{
		URL:        publicURL,
		Title:      e.Title,
		Breadcrumb: breadcrumbFromURL(publicURL),
		Content:    string(body),
	}, nil
}

// deriveHumanURL maps https://docs.vulncheck.com/raw/foo/bar.md →
//                  https://docs.vulncheck.com/foo/bar
// so citations point users to the actual viewable page.
func deriveHumanURL(rawURL string) string {
	u := strings.Replace(rawURL, "/raw/", "/", 1)
	u = strings.TrimSuffix(u, ".md")
	return u
}

// breadcrumbFromURL turns /products/exploit-and-vulnerability-intelligence/exploit-intelligence
// into "Products > Exploit And Vulnerability Intelligence > Exploit Intelligence".
// Cheap heuristic but gives the agent useful section context for searches.
func breadcrumbFromURL(publicURL string) string {
	idx := strings.Index(publicURL, "docs.vulncheck.com/")
	if idx < 0 {
		return ""
	}
	path := publicURL[idx+len("docs.vulncheck.com/"):]
	parts := strings.Split(path, "/")
	for i, p := range parts {
		parts[i] = titleCase(strings.ReplaceAll(p, "-", " "))
	}
	return strings.Join(parts, " > ")
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) == 0 {
			continue
		}
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " ")
}
