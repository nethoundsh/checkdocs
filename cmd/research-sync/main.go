// Command research-sync ingests VulnCheck vulnerability-research Jupyter notebooks
// into the docs SQLite database for use by the checkdocs agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/nethoundsh/checkdocs/internal/index"
	"github.com/nethoundsh/checkdocs/internal/research"
)

func main() {
	researchDir := flag.String("research", "research", "path to the vulnerability-research directory")
	dbPath := flag.String("db", "data/docs.db", "path to the docs SQLite database")
	verbose := flag.Bool("v", false, "verbose output")
	flag.Parse()

	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	db, err := index.Open(*dbPath)
	if err != nil {
		log.Error("open db", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	pages, err := research.Walk(*researchDir)
	if err != nil {
		log.Error("walk research dir", "path", *researchDir, "err", err)
		os.Exit(1)
	}

	if len(pages) == 0 {
		fmt.Fprintln(os.Stderr, "no notebooks found in", *researchDir)
		os.Exit(1)
	}

	ctx := context.Background()
	now := time.Now().Unix()
	var ok, failed int
	for _, p := range pages {
		err := db.Upsert(ctx, index.Page{
			URL:        p.URL,
			Title:      p.Title,
			Breadcrumb: p.Breadcrumb,
			Content:    p.Content,
		}, now)
		if err != nil {
			log.Error("upsert", "url", p.URL, "err", err)
			failed++
			continue
		}
		log.Info("indexed", "url", p.URL, "title", p.Title, "content_bytes", len(p.Content))
		ok++
	}

	fmt.Printf("research-sync: %d indexed, %d failed\n", ok, failed)
	if failed > 0 {
		os.Exit(1)
	}
}
