// Package index provides a SQLite-backed full-text index over scraped docs.
package index

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type Page struct {
	URL        string
	Title      string
	Breadcrumb string
	Content    string
	Snippet    string // populated by Search, empty for Get
}

type DB struct {
	conn *sql.DB
}

// Open opens (and initializes if needed) the SQLite database at path.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// Pragmas: WAL mode for concurrent reads while scraper writes,
	// foreign keys on for safety, busy timeout for friendlier locking.
	pragmas := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA foreign_keys=ON`,
		`PRAGMA busy_timeout=5000`,
	}
	for _, p := range pragmas {
		if _, err := conn.Exec(p); err != nil {
			return nil, fmt.Errorf("pragma %q: %w", p, err)
		}
	}
	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

func (db *DB) Close() error { return db.conn.Close() }

func (db *DB) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS pages (
			url        TEXT PRIMARY KEY,
			title      TEXT NOT NULL,
			breadcrumb TEXT NOT NULL DEFAULT '',
			content    TEXT NOT NULL,
			fetched_at INTEGER NOT NULL
		)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS pages_fts USING fts5(
			title, breadcrumb, content,
			content='pages', content_rowid='rowid',
			tokenize='porter unicode61'
		)`,
		// Triggers keep FTS in sync with the base table.
		`CREATE TRIGGER IF NOT EXISTS pages_ai AFTER INSERT ON pages BEGIN
			INSERT INTO pages_fts(rowid, title, breadcrumb, content)
			VALUES (new.rowid, new.title, new.breadcrumb, new.content);
		END`,
		`CREATE TRIGGER IF NOT EXISTS pages_ad AFTER DELETE ON pages BEGIN
			INSERT INTO pages_fts(pages_fts, rowid, title, breadcrumb, content)
			VALUES('delete', old.rowid, old.title, old.breadcrumb, old.content);
		END`,
		`CREATE TRIGGER IF NOT EXISTS pages_au AFTER UPDATE ON pages BEGIN
			INSERT INTO pages_fts(pages_fts, rowid, title, breadcrumb, content)
			VALUES('delete', old.rowid, old.title, old.breadcrumb, old.content);
			INSERT INTO pages_fts(rowid, title, breadcrumb, content)
			VALUES (new.rowid, new.title, new.breadcrumb, new.content);
		END`,
	}
	for _, s := range stmts {
		if _, err := db.conn.Exec(s); err != nil {
			return fmt.Errorf("exec %q: %w", s, err)
		}
	}
	return nil
}

// Upsert inserts or replaces a page. Idempotent — safe to re-run the scraper.
func (db *DB) Upsert(ctx context.Context, p Page, fetchedAt int64) error {
	_, err := db.conn.ExecContext(ctx, `
		INSERT INTO pages (url, title, breadcrumb, content, fetched_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(url) DO UPDATE SET
			title = excluded.title,
			breadcrumb = excluded.breadcrumb,
			content = excluded.content,
			fetched_at = excluded.fetched_at
	`, p.URL, p.Title, p.Breadcrumb, p.Content, fetchedAt)
	return err
}

// Get retrieves a single page by URL.
func (db *DB) Get(ctx context.Context, url string) (*Page, error) {
	var p Page
	err := db.conn.QueryRowContext(ctx,
		`SELECT url, title, breadcrumb, content FROM pages WHERE url = ?`, url,
	).Scan(&p.URL, &p.Title, &p.Breadcrumb, &p.Content)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Search runs an FTS5 MATCH query and returns ranked results with snippets.
func (db *DB) Search(ctx context.Context, query string, limit int) ([]Page, error) {
	if limit <= 0 || limit > 20 {
		limit = 5
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT p.url, p.title, p.breadcrumb,
		       snippet(pages_fts, 2, '<b>', '</b>', '…', 20) AS snip
		FROM pages_fts
		JOIN pages p ON p.rowid = pages_fts.rowid
		WHERE pages_fts MATCH ?
		ORDER BY bm25(pages_fts)
		LIMIT ?
	`, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Page
	for rows.Next() {
		var p Page
		if err := rows.Scan(&p.URL, &p.Title, &p.Breadcrumb, &p.Snippet); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
