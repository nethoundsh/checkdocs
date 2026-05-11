// Package agent implements a tool-using LLM loop over the VulnCheck docs index.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/shared"

	"github.com/nethoundsh/checkdocs/internal/index"
)

const systemPrompt = `You are a documentation assistant for VulnCheck, a vulnerability intelligence platform. You answer questions using ONLY the official VulnCheck documentation, accessible via the tools provided.

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
- If the docs don't cover something, say so plainly. Do not guess or fall back on general knowledge.
- When multiple pages share a title (e.g., several "Introduction" pages), disambiguate by breadcrumb or URL.`

const (
	toolSearchDocs = "search_docs"
	toolFetchPage  = "fetch_page"
)

// Tools returns the OpenAI-format tool definitions for this agent.
func Tools() []openai.ChatCompletionToolParam {
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

// Event is the unit of progress the agent emits during a run.
// The CLI prints these; the web server will serialize them as SSE messages.
type Event struct {
	Type    string // "tool_call", "tool_result", "token", "done", "error"
	Name    string // tool name, for tool_call / tool_result
	Args    string // raw JSON args, for tool_call
	Result  string // short human summary, for tool_result
	Content string // streamed token text, or error message
}

// Agent runs a single conversation against an OpenAI-compatible endpoint.
type Agent struct {
	client openai.Client
	idx    *index.DB
	model  string
	log    *slog.Logger
}

// New constructs an agent. apiKey is the OpenRouter key; baseURL ends with "/v1/".
func New(apiKey, baseURL, model string, idx *index.DB, log *slog.Logger) *Agent {
	client := openai.NewClient(
		option.WithAPIKey(apiKey),
		option.WithBaseURL(baseURL),
	)
	return &Agent{
		client: client,
		idx:    idx,
		model:  model,
		log:    log,
	}
}

// Run executes the agent loop for a single user question, emitting events to
// the provided channel. Closes the channel when done.
func (a *Agent) Run(ctx context.Context, userQuestion string, out chan<- Event) {
	defer close(out)

	messages := []openai.ChatCompletionMessageParamUnion{
		openai.SystemMessage(systemPrompt),
		openai.UserMessage(userQuestion),
	}

	const maxIterations = 16
	for i := 0; i < maxIterations; i++ {
		stream := a.client.Chat.Completions.NewStreaming(ctx, openai.ChatCompletionNewParams{
			Model:    a.model,
			Messages: messages,
			Tools:    Tools(),
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
				out <- Event{Type: "done"}
			} else {
				out <- Event{Type: "error", Content: "empty response with no tool calls"}
			}
			return
		}

		// Otherwise execute the tools and loop.
		for _, tc := range msg.ToolCalls {
			out <- Event{Type: "tool_call", Name: tc.Function.Name, Args: tc.Function.Arguments}

			result, summary, err := a.dispatch(ctx, tc.Function.Name, tc.Function.Arguments)
			if err != nil {
				result = fmt.Sprintf("error: %v", err)
				summary = result
			}
			out <- Event{Type: "tool_result", Name: tc.Function.Name, Result: summary}

			messages = append(messages, openai.ToolMessage(result, tc.ID))
		}
	}

	out <- Event{Type: "error", Content: fmt.Sprintf("max iterations (%d) reached", maxIterations)}
}

// dispatch executes a tool call. Returns (fullResult, shortSummary, error).
// fullResult goes back to the model; summary is what the human sees.
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

	default:
		return "", "", fmt.Errorf("unknown tool: %s", name)
	}
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
