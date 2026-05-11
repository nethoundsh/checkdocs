// Package agent implements a tool-using LLM loop over the VulnCheck docs index.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/shared"

	"github.com/nethoundsh/checkdocs/internal/index"
	"github.com/nethoundsh/checkdocs/internal/vulncheck"
)

// Session holds the message history for a multi-turn conversation.
// All methods are safe for concurrent use.
type Session struct {
	mu       sync.Mutex
	messages []openai.ChatCompletionMessageParamUnion
}

// NewSession creates a session pre-loaded with the system prompt.
func NewSession() *Session {
	return &Session{
		messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage(baseSystemPrompt),
		},
	}
}

func (s *Session) snapshot() []openai.ChatCompletionMessageParamUnion {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]openai.ChatCompletionMessageParamUnion, len(s.messages))
	copy(cp, s.messages)
	return cp
}

func (s *Session) commit(messages []openai.ChatCompletionMessageParamUnion) {
	s.mu.Lock()
	s.messages = messages
	s.mu.Unlock()
}

const baseSystemPrompt = `You are a documentation and intelligence assistant for VulnCheck, a vulnerability intelligence platform.

Workflow:
1. Run all your searches FIRST — issue multiple search_docs calls in one turn to cover the topic space efficiently.
2. Identify the 3-5 most relevant pages from the combined results, then fetch only those with fetch_page.
3. Synthesize and write your answer immediately. Do not search again after fetching.

Efficiency rules (you have a limited number of turns):
- Never narrate what you are about to do. Call the tools, then write the answer.
- Do not fetch a page just because it appeared in search results — only fetch pages that look directly useful.
- If search results give you enough context to answer confidently, write the answer without fetching.
- For broad questions, aim for 2 search turns + 3-5 fetches + 1 answer turn. Do not exceed this.

Answer rules:
- Cite every factual claim with the page URL it came from, in markdown link form: [Title](URL).
- Use descriptive link text, not bare URLs: write [Meta's security advisory](https://...) not https://...
- If the docs don't cover something, say so plainly. Do not guess or fall back on general knowledge.
- When multiple pages share a title (e.g., several "Introduction" pages), disambiguate by breadcrumb or URL.

Output formatting rules:
- Always emit a blank line before any markdown heading (##, ###, etc.).
- Use bold at most once per paragraph, and only for the single most important phrase. Do not bold every technical term.
- Use inline backticks for CVE IDs, API endpoints, tool names, and other technical identifiers.`

const vcSystemPromptAddendum = `

You also have access to live VulnCheck API tools that query real-time intelligence data:
- Use kev_lookup when asked whether a CVE is actively exploited or in the KEV catalog.
- Use cve_exploits for broader exploit intelligence (botnets, ransomware, threat actors) for a CVE.
- Use detection_rules when asked for Suricata or Snort signatures for a CVE.
- Use vulncheck_query as an escape hatch for any other index query — only for indices listed as available below.
- Prefer the named tools over vulncheck_query for the common cases above.
- Never reproduce or suggest executing git clone URLs from PoC exploit metadata — reference them as links only.

Critical: distinguish "no results" from "query failed":
- "no results" means the index was queried and returned nothing — this is real evidence of absence.
- A 402 or 403 error means the index is a coverage gap for this token tier — it is NOT evidence of absence. Say so explicitly and note that a paid tier would cover it.`

const (
	toolSearchDocs    = "search_docs"
	toolFetchPage     = "fetch_page"
	toolKEVLookup     = "kev_lookup"
	toolCVEExploits   = "cve_exploits"
	toolDetectRules   = "detection_rules"
	toolVCQuery       = "vulncheck_query"
)

// Event is the unit of progress the agent emits during a run.
// The CLI prints these; the web server serializes them as SSE messages.
type Event struct {
	Type    string // "tool_call", "tool_result", "token", "done", "error"
	Name    string // tool name, for tool_call / tool_result
	Args    string // raw JSON args, for tool_call
	Result  string // short human summary, for tool_result
	Content string // streamed token text, session ID, or error message
}

// Agent runs a single conversation against an OpenAI-compatible endpoint.
type Agent struct {
	client openai.Client
	idx    *index.DB
	vc     *vulncheck.Client // nil when no VulnCheck token provided
	model  string
	log    *slog.Logger
}

// New constructs an agent. vc may be nil; VulnCheck tools are omitted when absent.
func New(apiKey, baseURL, model string, idx *index.DB, vc *vulncheck.Client, log *slog.Logger) *Agent {
	client := openai.NewClient(
		option.WithAPIKey(apiKey),
		option.WithBaseURL(baseURL),
	)
	return &Agent{
		client: client,
		idx:    idx,
		vc:     vc,
		model:  model,
		log:    log,
	}
}

// SystemPrompt returns the system prompt appropriate for this agent's configuration.
func (a *Agent) SystemPrompt() string {
	if a.vc != nil {
		return baseSystemPrompt + vcSystemPromptAddendum
	}
	return baseSystemPrompt
}

// tools returns the tool definitions to pass to the model, conditionally
// including VulnCheck API tools when a client is configured.
func (a *Agent) tools() []openai.ChatCompletionToolParam {
	t := docTools()
	if a.vc != nil {
		t = append(t, vcTools()...)
	}
	return t
}

func docTools() []openai.ChatCompletionToolParam {
	return []openai.ChatCompletionToolParam{
		{
			Function: shared.FunctionDefinitionParam{
				Name:        toolSearchDocs,
				Description: openai.String("Full-text (BM25) search over VulnCheck documentation. Returns up to N pages with highlighted snippets. Use specific keywords — this is keyword search, not semantic. Title and breadcrumb are weighted heavily."),
				Parameters: shared.FunctionParameters{
					"type": "object",
					"properties": map[string]any{
						"query": map[string]any{
							"type":        "string",
							"description": "Keywords to search for. Example: 'api token authentication' or 'rate limit'.",
						},
						"limit": map[string]any{
							"type":        "integer",
							"description": "Max results (default 5, max 10).",
						},
					},
					"required": []string{"query"},
				},
			},
		},
		{
			Function: shared.FunctionDefinitionParam{
				Name:        toolFetchPage,
				Description: openai.String("Retrieve the full markdown content of a documentation page by its URL. Use after search_docs identifies a relevant page."),
				Parameters: shared.FunctionParameters{
					"type": "object",
					"properties": map[string]any{
						"url": map[string]any{
							"type":        "string",
							"description": "Canonical page URL as returned by search_docs.",
						},
					},
					"required": []string{"url"},
				},
			},
		},
	}
}

func vcTools() []openai.ChatCompletionToolParam {
	return []openai.ChatCompletionToolParam{
		{
			Function: shared.FunctionDefinitionParam{
				Name:        toolKEVLookup,
				Description: openai.String("Check whether a CVE is in the VulnCheck KEV catalog. Returns date added, ransomware campaign association, and linked PoC exploit metadata. Available on the community (free) tier."),
				Parameters: shared.FunctionParameters{
					"type": "object",
					"properties": map[string]any{
						"cve_id": map[string]any{
							"type":        "string",
							"description": "CVE identifier, e.g. 'CVE-2021-44228'.",
						},
					},
					"required": []string{"cve_id"},
				},
			},
		},
		{
			Function: shared.FunctionDefinitionParam{
				Name:        toolCVEExploits,
				Description: openai.String("Retrieve exploit intelligence for a CVE across all available indices (initial-access, botnets, ransomware, threat-actors). Only queries indices the token has access to. Queries run concurrently for speed."),
				Parameters: shared.FunctionParameters{
					"type": "object",
					"properties": map[string]any{
						"cve_id": map[string]any{
							"type":        "string",
							"description": "CVE identifier, e.g. 'CVE-2021-44228'.",
						},
					},
					"required": []string{"cve_id"},
				},
			},
		},
		{
			Function: shared.FunctionDefinitionParam{
				Name:        toolDetectRules,
				Description: openai.String("Fetch network detection rules for a CVE from the VulnCheck initial-access rules endpoint. Requires paid tier access to the initial-access index."),
				Parameters: shared.FunctionParameters{
					"type": "object",
					"properties": map[string]any{
						"cve_id": map[string]any{
							"type":        "string",
							"description": "CVE identifier, e.g. 'CVE-2021-44228'.",
						},
						"format": map[string]any{
							"type":        "string",
							"enum":        []string{"suricata", "snort"},
							"description": "Rule format: 'suricata' or 'snort'.",
						},
					},
					"required": []string{"cve_id", "format"},
				},
			},
		},
		{
			Function: shared.FunctionDefinitionParam{
				Name:        toolVCQuery,
				Description: openai.String("Query any VulnCheck index directly. Use when the named tools don't cover the question. Omit cve to browse an index generally."),
				Parameters: shared.FunctionParameters{
					"type": "object",
					"properties": map[string]any{
						"index": map[string]any{
							"type":        "string",
							"description": "Index name, e.g. 'vulncheck-kev', 'botnets', 'initial-access'. Call GET /v3/index to list available indices.",
						},
						"cve": map[string]any{
							"type":        "string",
							"description": "Optional CVE filter, e.g. 'CVE-2021-44228'.",
						},
						"limit": map[string]any{
							"type":        "integer",
							"description": "Max results (default 5).",
						},
					},
					"required": []string{"index"},
				},
			},
		},
	}
}

// Run executes the agent loop for one user turn, appending to sess and
// committing the updated history on success. Closes out when done.
func (a *Agent) Run(ctx context.Context, sess *Session, userQuestion string, out chan<- Event) {
	defer close(out)

	// Use a session with the right system prompt for this agent configuration.
	// If the session was created before a VulnCheck token was added, patch it.
	messages := sess.snapshot()
	if len(messages) > 0 {
		prompt := a.SystemPrompt()
		// Inject available indices up-front so the model knows what it can
		// query before making tool calls, avoiding reactive 402 discovery.
		if a.vc != nil {
			if avail, err := a.vc.AvailableIndices(ctx); err == nil && len(avail) > 0 {
				names := make([]string, 0, len(avail))
				for name := range avail {
					names = append(names, name)
				}
				sort.Strings(names)
				prompt += "\n\nVulnCheck indices available for this token: " +
					strings.Join(names, ", ") +
					". Do not call vulncheck_query with indices not on this list — they will fail with a tier error."
			}
		}
		messages[0] = openai.SystemMessage(prompt)
	}
	messages = append(messages, openai.UserMessage(userQuestion))

	const maxIterations = 16
	for i := 0; i < maxIterations; i++ {
		stream := a.client.Chat.Completions.NewStreaming(ctx, openai.ChatCompletionNewParams{
			Model:    a.model,
			Messages: messages,
			Tools:    a.tools(),
		})

		acc := openai.ChatCompletionAccumulator{}
		var emittedAnyToken bool

		for stream.Next() {
			chunk := stream.Current()
			acc.AddChunk(chunk)

			if len(chunk.Choices) > 0 {
				if delta := chunk.Choices[0].Delta.Content; delta != "" {
					out <- Event{Type: "token", Content: delta}
					emittedAnyToken = true
				}
			}
		}

		if err := stream.Err(); err != nil {
			out <- Event{Type: "error", Content: fmt.Sprintf("stream: %v", err)}
			return
		}

		if len(acc.Choices) == 0 {
			out <- Event{Type: "error", Content: "no choices in response"}
			return
		}

		msg := acc.Choices[0].Message
		messages = append(messages, msg.ToParam())

		// If the model didn't call any tools, we already streamed the answer. Done.
		if len(msg.ToolCalls) == 0 {
			if emittedAnyToken {
				sess.commit(messages)
				out <- Event{Type: "done"}
			} else {
				out <- Event{Type: "error", Content: "empty response with no tool calls"}
			}
			return
		}

		// Emit all tool_call events before dispatching, then run dispatches
		// concurrently. Results are collected into a pre-indexed slice so the
		// goroutines never share a write target; no mutex required.
		type toolOutcome struct {
			tc      openai.ChatCompletionMessageToolCall
			result  string
			summary string
		}
		outcomes := make([]toolOutcome, len(msg.ToolCalls))
		for i, tc := range msg.ToolCalls {
			outcomes[i].tc = tc
			out <- Event{Type: "tool_call", Name: tc.Function.Name, Args: tc.Function.Arguments}
		}

		var wg sync.WaitGroup
		for i, tc := range msg.ToolCalls {
			wg.Add(1)
			go func(i int, tc openai.ChatCompletionMessageToolCall) {
				defer wg.Done()
				result, summary, err := a.dispatch(ctx, tc.Function.Name, tc.Function.Arguments)
				if err != nil {
					result = fmt.Sprintf("error: %v", err)
					summary = result
				}
				outcomes[i].result = result
				outcomes[i].summary = summary
			}(i, tc)
		}
		wg.Wait()

		for _, o := range outcomes {
			out <- Event{Type: "tool_result", Name: o.tc.Function.Name, Result: o.summary}
			messages = append(messages, openai.ToolMessage(o.result, o.tc.ID))
		}
	}

	sess.commit(messages) // preserve context even though we didn't finish
	out <- Event{Type: "error", Content: fmt.Sprintf("max iterations (%d) reached", maxIterations)}
}

// dispatch executes a tool call. Returns (fullResult, shortSummary, error).
func (a *Agent) dispatch(ctx context.Context, name, rawArgs string) (string, string, error) {
	switch name {
	case toolSearchDocs:
		var args struct {
			Query string `json:"query"`
			Limit int    `json:"limit"`
		}
		if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
			return "", "", fmt.Errorf("parse args: %w", err)
		}
		if args.Limit == 0 {
			args.Limit = 5
		}
		pages, err := a.idx.Search(ctx, args.Query, args.Limit)
		if err != nil {
			return "", "", fmt.Errorf("search: %w", err)
		}
		return formatSearchResult(args.Query, pages), fmt.Sprintf("%d pages", len(pages)), nil

	case toolFetchPage:
		var args struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
			return "", "", fmt.Errorf("parse args: %w", err)
		}
		page, err := a.idx.Get(ctx, args.URL)
		if err != nil {
			return "", "", fmt.Errorf("get: %w", err)
		}
		if page == nil {
			return fmt.Sprintf("No page found at %s", args.URL), "not found", nil
		}
		return formatPage(page), fmt.Sprintf("%s (%d bytes)", page.Title, len(page.Content)), nil

	case toolKEVLookup:
		return a.dispatchKEVLookup(ctx, rawArgs)

	case toolCVEExploits:
		return a.dispatchCVEExploits(ctx, rawArgs)

	case toolDetectRules:
		return a.dispatchDetectionRules(ctx, rawArgs)

	case toolVCQuery:
		return a.dispatchVCQuery(ctx, rawArgs)

	default:
		return "", "", fmt.Errorf("unknown tool: %s", name)
	}
}

func (a *Agent) dispatchKEVLookup(ctx context.Context, rawArgs string) (string, string, error) {
	var args struct {
		CVEID string `json:"cve_id"`
	}
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return "", "", fmt.Errorf("parse args: %w", err)
	}

	params := url.Values{"cve": {args.CVEID}}
	entries, err := a.vc.QueryIndex(ctx, "vulncheck-kev", params)
	if err != nil {
		return "", "", err
	}
	if len(entries) == 0 {
		msg := fmt.Sprintf("%s is not in the VulnCheck KEV catalog.", args.CVEID)
		return msg, "not in KEV", nil
	}

	// Pretty-print the first entry; omit raw clone URLs from the summary.
	pretty, _ := json.MarshalIndent(entries[0], "", "  ")
	return fmt.Sprintf("VulnCheck KEV entry for %s:\n\n```json\n%s\n```", args.CVEID, pretty),
		fmt.Sprintf("in KEV (%s)", args.CVEID), nil
}

func (a *Agent) dispatchCVEExploits(ctx context.Context, rawArgs string) (string, string, error) {
	var args struct {
		CVEID string `json:"cve_id"`
	}
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return "", "", fmt.Errorf("parse args: %w", err)
	}

	indices := []string{"initial-access", "botnets", "ransomware", "threat-actors"}
	params := url.Values{"cve": {args.CVEID}, "limit": {"5"}}

	type indexResult struct {
		name    string
		entries []json.RawMessage
		err     error
	}

	results := make([]indexResult, len(indices))
	var wg sync.WaitGroup
	for i, idx := range indices {
		if !a.vc.HasIndex(ctx, idx) {
			continue
		}
		wg.Add(1)
		go func(i int, idx string) {
			defer wg.Done()
			entries, err := a.vc.QueryIndex(ctx, idx, params)
			results[i] = indexResult{name: idx, entries: entries, err: err}
		}(i, idx)
	}
	wg.Wait()

	var sb strings.Builder
	var counts []string
	sb.WriteString(fmt.Sprintf("Exploit intelligence for %s:\n\n", args.CVEID))

	for _, r := range results {
		if r.name == "" || r.err != nil || len(r.entries) == 0 {
			continue
		}
		counts = append(counts, fmt.Sprintf("%s (%d)", r.name, len(r.entries)))
		pretty, _ := json.MarshalIndent(r.entries, "", "  ")
		sb.WriteString(fmt.Sprintf("### %s\n```json\n%s\n```\n\n", r.name, pretty))
	}

	if len(counts) == 0 {
		return fmt.Sprintf("No exploit intelligence found for %s in available indices.", args.CVEID),
			"no results", nil
	}
	return sb.String(), strings.Join(counts, ", "), nil
}

func (a *Agent) dispatchDetectionRules(ctx context.Context, rawArgs string) (string, string, error) {
	var args struct {
		CVEID  string `json:"cve_id"`
		Format string `json:"format"`
	}
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return "", "", fmt.Errorf("parse args: %w", err)
	}

	rules, err := a.vc.DetectionRules(ctx, args.CVEID, args.Format)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(rules) == "" {
		return fmt.Sprintf("No %s rules found for %s.", args.Format, args.CVEID),
			"no rules found", nil
	}

	// Count rules by looking for "alert" keyword lines (Suricata/Snort convention).
	count := strings.Count(rules, "\nalert ") + strings.Count(rules, "\nalert\t")
	if strings.HasPrefix(rules, "alert") {
		count++
	}

	result := fmt.Sprintf("%s rules for %s:\n\n```\n%s\n```", args.Format, args.CVEID, rules)
	summary := fmt.Sprintf("%d %s rules", count, args.Format)
	if count == 0 {
		summary = fmt.Sprintf("%s rules returned", args.Format)
	}
	return result, summary, nil
}

func (a *Agent) dispatchVCQuery(ctx context.Context, rawArgs string) (string, string, error) {
	var args struct {
		Index string `json:"index"`
		CVE   string `json:"cve"`
		Limit int    `json:"limit"`
	}
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return "", "", fmt.Errorf("parse args: %w", err)
	}
	if args.Limit == 0 {
		args.Limit = 5
	}

	params := url.Values{"limit": {fmt.Sprintf("%d", args.Limit)}}
	if args.CVE != "" {
		params.Set("cve", args.CVE)
	}

	entries, err := a.vc.QueryIndex(ctx, args.Index, params)
	if err != nil {
		return "", "", err
	}

	if len(entries) == 0 {
		return fmt.Sprintf("No results in index %q%s.", args.Index, cveClause(args.CVE)),
			"0 results", nil
	}

	pretty, _ := json.MarshalIndent(entries, "", "  ")
	return fmt.Sprintf("Results from index %q%s:\n\n```json\n%s\n```",
		args.Index, cveClause(args.CVE), pretty),
		fmt.Sprintf("%d results from %s", len(entries), args.Index), nil
}

func cveClause(cve string) string {
	if cve == "" {
		return ""
	}
	return " for " + cve
}

func formatSearchResult(query string, pages []index.Page) string {
	if len(pages) == 0 {
		return fmt.Sprintf("No results for %q.", query)
	}
	out := fmt.Sprintf("Found %d results for %q:\n\n", len(pages), query)
	for i, p := range pages {
		out += fmt.Sprintf("%d. **%s**\n   URL: %s\n   Breadcrumb: %s\n   Snippet: %s\n\n",
			i+1, p.Title, p.URL, p.Breadcrumb, p.Snippet)
	}
	return out
}

func formatPage(p *index.Page) string {
	return fmt.Sprintf("# %s\n\nURL: %s\nBreadcrumb: %s\n\n---\n\n%s",
		p.Title, p.URL, p.Breadcrumb, p.Content)
}
