// Command server runs the checkdocs HTTP API and minimal web UI.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/nethoundsh/checkdocs/internal/agent"
	"github.com/nethoundsh/checkdocs/internal/index"
)

const (
	openRouterBaseURL = "https://openrouter.ai/api/v1/"
	defaultModel      = "anthropic/claude-sonnet-4.5"
)

//go:embed all:web
var webFS embed.FS

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dbPath := flag.String("db", "data/docs.db", "path to SQLite database")
	model := flag.String("model", defaultModel, "default OpenRouter model")
	flag.Parse()

	_ = godotenv.Load()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	db, err := index.Open(*dbPath)
	if err != nil {
		log.Error("open db", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	mux := http.NewServeMux()

	// Static UI served from embedded FS.
	uiFS, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Error("embed sub", "err", err)
		os.Exit(1)
	}
	mux.Handle("/", http.FileServer(http.FS(uiFS)))

	mux.HandleFunc("POST /api/chat", chatHandler(db, *model, log))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: SSE responses are long-lived by design.
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		log.Info("server listening", "addr", *addr, "model", *model)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen", "err", err)
			cancel()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
}

// chatRequest is what the browser POSTs.
type chatRequest struct {
	Question string `json:"question"`
	Model    string `json:"model,omitempty"` // optional override
}

// chatHandler streams the agent's events as Server-Sent Events.
func chatHandler(db *index.DB, defaultModel string, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// BYOK: the user's key arrives as a header. Never log it.
		apiKey := strings.TrimSpace(r.Header.Get("X-OpenRouter-Key"))
		if apiKey == "" {
			http.Error(w, "missing X-OpenRouter-Key header", http.StatusUnauthorized)
			return
		}

		var req chatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json body", http.StatusBadRequest)
			return
		}
		req.Question = strings.TrimSpace(req.Question)
		if req.Question == "" {
			http.Error(w, "empty question", http.StatusBadRequest)
			return
		}
		if len(req.Question) > 8000 {
			http.Error(w, "question too long (max 8000 chars)", http.StatusBadRequest)
			return
		}
		model := req.Model
		if model == "" {
			model = defaultModel
		}

		// SSE headers. Flush after each event so the browser sees them live.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering (nginx/cloudflare)

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		log.Info("chat", "model", model, "q_len", len(req.Question))

		ag := agent.New(apiKey, openRouterBaseURL, model, db, log)

		events := make(chan agent.Event, 16)
		go ag.Run(r.Context(), req.Question, events)

		for ev := range events {
			if err := writeSSE(w, ev); err != nil {
				log.Warn("sse write", "err", err)
				return
			}
			flusher.Flush()
		}
	}
}

// writeSSE serializes one event as `event: <type>\ndata: <json>\n\n`.
// Splitting type into the event field lets the client use addEventListener
// per type instead of branching inside a single onmessage handler.
func writeSSE(w http.ResponseWriter, ev agent.Event) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, payload)
	return err
}
