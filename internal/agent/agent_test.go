package agent

import (
	"log/slog"
	"os"
	"testing"

	"github.com/nethoundsh/checkdocs/internal/brave"
	"github.com/nethoundsh/checkdocs/internal/vulncheck"
)

func silentLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// newTestAgent builds an Agent suitable for unit tests. idx is nil — only
// call methods that don't touch the database (e.g. tools(), systemPrompt()).
func newTestAgent(vc *vulncheck.Client, br *brave.Client, hasResearch bool) *Agent {
	return New("test-key", OpenRouterBaseURL, "test-model", nil, vc, br, hasResearch, silentLog())
}

func TestToolsDocOnly(t *testing.T) {
	a := newTestAgent(nil, nil, false)
	tools := a.tools()
	if len(tools) != 2 {
		t.Fatalf("doc-only: got %d tools, want 2", len(tools))
	}
	if tools[0].Function.Name != toolSearchDocs {
		t.Errorf("tools[0]: got %q, want %q", tools[0].Function.Name, toolSearchDocs)
	}
	if tools[1].Function.Name != toolFetchPage {
		t.Errorf("tools[1]: got %q, want %q", tools[1].Function.Name, toolFetchPage)
	}
}

func TestToolsWithVulnCheck(t *testing.T) {
	a := newTestAgent(vulncheck.NewClient("test"), nil, false)
	// 2 doc tools + 7 VulnCheck tools
	if got := len(a.tools()); got != 9 {
		t.Errorf("with vc: got %d tools, want 9", got)
	}
}

func TestToolsWithBrave(t *testing.T) {
	a := newTestAgent(nil, brave.NewClient("test"), false)
	// 2 doc tools + 2 Brave tools
	if got := len(a.tools()); got != 4 {
		t.Errorf("with brave: got %d tools, want 4", got)
	}
}

func TestToolsWithResearch(t *testing.T) {
	a := newTestAgent(nil, nil, true)
	// 2 doc tools + 1 research tool
	if got := len(a.tools()); got != 3 {
		t.Errorf("with research: got %d tools, want 3", got)
	}
}

func TestToolsAllEnabled(t *testing.T) {
	a := newTestAgent(vulncheck.NewClient("test"), brave.NewClient("test"), true)
	// 2 doc + 7 vc + 1 research + 2 brave
	if got := len(a.tools()); got != 12 {
		t.Errorf("all enabled: got %d tools, want 12", got)
	}
}

func TestCVEIDRegex(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"CVE-2021-44228 is Log4Shell", []string{"CVE-2021-44228"}},
		{"CVE-2024-1234567 has a 7-digit ID", []string{"CVE-2024-1234567"}},
		{"Multiple: CVE-2021-1234 and CVE-2022-56789", []string{"CVE-2021-1234", "CVE-2022-56789"}},
		{"no CVEs here", nil},
		{"invalid CV-2021-44228 not matched", nil},
		{"invalid CVE-21-44228 too short year", nil},
		{"invalid CVE-2021-123 too few digits", nil},
	}
	for _, tc := range cases {
		got := cveIDRe.FindAllString(tc.input, -1)
		if len(got) != len(tc.want) {
			t.Errorf("input=%q: got %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("input=%q [%d]: got %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}
