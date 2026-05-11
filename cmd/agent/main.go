package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"

	"github.com/nethoundsh/checkdocs/internal/agent"
	"github.com/nethoundsh/checkdocs/internal/index"
	"github.com/nethoundsh/checkdocs/internal/vulncheck"
)

const (
	openRouterBaseURL = "https://openrouter.ai/api/v1/"
	defaultModel      = "anthropic/claude-sonnet-4.5"
)

func main() {
	dbPath := flag.String("db", "data/docs.db", "path to SQLite database")
	model := flag.String("model", defaultModel, "OpenRouter model identifier (e.g. anthropic/claude-sonnet-4.5, google/gemini-2.5-pro)")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: agent [-model M] [-db PATH] \"<question>\"")
		os.Exit(2)
	}
	question := flag.Arg(0)

	_ = godotenv.Load()
	apiKey := os.Getenv("OPENROUTER_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "OPENROUTER_API_KEY not set (use .env or shell env)")
		os.Exit(1)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	db, err := index.Open(*dbPath)
	if err != nil {
		log.Error("open db", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	var vc *vulncheck.Client
	if vcToken := os.Getenv("VULNCHECK_API_TOKEN"); vcToken != "" {
		vc = vulncheck.NewClient(vcToken)
	}

	ag := agent.New(apiKey, openRouterBaseURL, *model, db, vc, log)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	events := make(chan agent.Event, 16)
	go ag.Run(ctx, agent.NewSession(), question, events)

	for ev := range events {
		switch ev.Type {
		case "tool_call":
			fmt.Fprintf(os.Stderr, "\n\033[36m→ %s(%s)\033[0m\n", ev.Name, ev.Args)
		case "tool_result":
			fmt.Fprintf(os.Stderr, "\033[32m  ✓ %s: %s\033[0m\n\n", ev.Name, ev.Result)
		case "token":
			fmt.Print(ev.Content)
		case "done":
			fmt.Println()
		case "error":
			fmt.Fprintf(os.Stderr, "\n\033[31m✗ %s\033[0m\n", ev.Content)
			os.Exit(1)
		}
	}
}
