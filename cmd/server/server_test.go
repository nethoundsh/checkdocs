package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nethoundsh/checkdocs/internal/agent"
	"github.com/nethoundsh/checkdocs/internal/index"
)

func openTestDB(t *testing.T) *index.DB {
	t.Helper()
	db, err := index.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func silentLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestWriteSSE verifies the SSE wire format: correct event type line, double
// newline terminator, and a valid JSON data payload that round-trips cleanly.
func TestWriteSSE(t *testing.T) {
	cases := []agent.Event{
		{Type: "token", Content: "hello world"},
		{Type: "done"},
		{Type: "tool_call", Name: "search_docs", Args: `{"query":"test"}`},
		{Type: "tool_result", Name: "search_docs", Result: "3 pages"},
		{Type: "error", Content: "something went wrong"},
	}

	for _, ev := range cases {
		rr := httptest.NewRecorder()
		if err := writeSSE(rr, ev); err != nil {
			t.Fatalf("writeSSE(%q): %v", ev.Type, err)
		}

		out := rr.Body.String()

		// Must start with the typed event line.
		wantPrefix := "event: " + ev.Type + "\n"
		if !strings.HasPrefix(out, wantPrefix) {
			t.Errorf("type=%q: got %q, want prefix %q", ev.Type, out, wantPrefix)
		}

		// Must end with double newline (SSE message boundary).
		if !strings.HasSuffix(out, "\n\n") {
			t.Errorf("type=%q: missing double-newline terminator in %q", ev.Type, out)
		}

		// Data line must contain valid JSON that round-trips the Type field.
		var dataLine string
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "data: ") {
				dataLine = strings.TrimPrefix(line, "data: ")
			}
		}
		var got agent.Event
		if err := json.Unmarshal([]byte(dataLine), &got); err != nil {
			t.Errorf("type=%q: data is not valid JSON: %v", ev.Type, err)
			continue
		}
		if got.Type != ev.Type {
			t.Errorf("type=%q: JSON Type round-trip: got %q", ev.Type, got.Type)
		}
	}
}

// TestChatHandlerValidation checks all early-return error paths that fire
// before the agent is ever created — no OpenRouter call is made.
func TestChatHandlerValidation(t *testing.T) {
	handler := chatHandler(openTestDB(t), defaultModel, newSessionStore(), silentLog())

	post := func(t *testing.T, body string, extraHeaders map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		handler(rr, req)
		return rr
	}

	t.Run("missing api key returns 401", func(t *testing.T) {
		rr := post(t, `{"question":"hello"}`, nil)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", rr.Code)
		}
	})

	t.Run("invalid json returns 400", func(t *testing.T) {
		rr := post(t, `not json`, map[string]string{"X-OpenRouter-Key": "sk-or-v1-test"})
		if rr.Code != http.StatusBadRequest {
			t.Errorf("got %d, want 400", rr.Code)
		}
	})

	t.Run("empty question returns 400", func(t *testing.T) {
		rr := post(t, `{"question":"   "}`, map[string]string{"X-OpenRouter-Key": "sk-or-v1-test"})
		if rr.Code != http.StatusBadRequest {
			t.Errorf("got %d, want 400", rr.Code)
		}
	})

	t.Run("question over 8000 chars returns 400", func(t *testing.T) {
		body, _ := json.Marshal(chatRequest{Question: strings.Repeat("a", 8001)})
		rr := post(t, string(body), map[string]string{"X-OpenRouter-Key": "sk-or-v1-test"})
		if rr.Code != http.StatusBadRequest {
			t.Errorf("got %d, want 400", rr.Code)
		}
	})

	t.Run("question at exactly 8000 chars passes validation", func(t *testing.T) {
		// Should not return 400 for the length check — it will fail later
		// when it tries to stream SSE (ResponseRecorder doesn't implement Flusher),
		// returning 500. That's fine — we're only testing the length boundary here.
		body, _ := json.Marshal(chatRequest{Question: strings.Repeat("a", 8000)})
		rr := post(t, string(body), map[string]string{"X-OpenRouter-Key": "sk-or-v1-test"})
		if rr.Code == http.StatusBadRequest && strings.Contains(rr.Body.String(), "too long") {
			t.Errorf("8000-char question should not be rejected by length check")
		}
	})
}
