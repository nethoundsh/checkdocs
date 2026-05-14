// Package agent implements a tool-using LLM loop over the VulnCheck docs index.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/shared"

	"github.com/nethoundsh/checkdocs/internal/brave"
	"github.com/nethoundsh/checkdocs/internal/index"
	"github.com/nethoundsh/checkdocs/internal/vulncheck"
)

// OpenRouterBaseURL is the OpenRouter API base used by both the CLI and server.
const OpenRouterBaseURL = "https://openrouter.ai/api/v1/"

var cveIDRe = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// Session holds the message history for a multi-turn conversation.
// All methods are safe for concurrent use.
type Session struct {
	mu       sync.Mutex
	messages []openai.ChatCompletionMessageParamUnion
}

// NewSession creates an empty session; Run sets the system prompt on first call.
func NewSession() *Session {
	return &Session{}
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
- Cite every factual claim inline, immediately after the claim, as a markdown link: [Source Title](URL).
- When a section draws from multiple sources, each sentence or clause that asserts a fact gets its own inline citation — do not collect all sources into a table at the end. Example: "The vulnerability was patched in version 25.1.8 ([OPNsense advisory](https://...)), and CISA rates it 8.8 High ([NVD entry](https://...))."
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
- Use search_cpe when asked about CVEs for a vendor or product (e.g. "Fortinet FortiOS vulnerabilities", "OPNsense CVEs"). Pass vendor and/or product as keyword strings; set is_vulnerable=true to restrict to directly vulnerable CPEs (recommended). This is the correct tool for vendor/product CVE enumeration — it works on community tier.
- Use identify to convert a natural-language (vendor, product, version) description into a canonical CPE before calling search_cpe, especially when the exact vendor/product slug is uncertain.
- Use purl_lookup when asked whether a specific package version is vulnerable (e.g. "is lodash 4.17.20 vulnerable?"). Package URL format: pkg:npm/lodash@4.17.20, pkg:pypi/requests@2.28.0, pkg:golang/github.com/foo/bar@v1.2.3.
- Use vulncheck_query as an escape hatch for any other index query — only for indices listed as available below.
- Prefer the named tools over vulncheck_query for the common cases above.
- Never reproduce or suggest executing git clone URLs from PoC exploit metadata — reference them as links only.
- When cve_exploits returns xdb results, use the maturity level to characterize exploitation risk: "poc" = lab reproduction (lower operational risk), "weaponized" = polished exploit module (higher operational risk). Always state which category applies rather than just noting "PoC available."

NVD index guidance (important):
- For vendor/product/version CVE enumeration, use search_cpe — it supports these parameters natively on community tier.
- Community-tier tokens include nist-nvd2 (NIST NVD 2.0) and nist-nvd (NIST NVD 1.0). Use these for exact CVE ID lookups only — they do NOT support vendor or keyword search.
- Paid-tier tokens additionally include vulncheck-nvd2 and vulncheck-nvd. Do NOT attempt these on a community token — they will 402.

Interpreting NVD CPE records accurately:
- NVD CPE entries often set versionEndExcluding without a lower bound. This means "NVD did not enumerate a lower bound" — NOT "the bug has existed since version 1.0." State only what the record says: "versions before X.Y.Z are affected per NVD."
- A versionStartIncluding of an ancient version does not mean the bug was introduced then — it may just be the earliest version the reporter tested. Attribute CPE bounds to their source.

Enumeration discipline:
- Never guess or iterate through CVE IDs. Use search_cpe, find_vendor_cves, or purl_lookup for enumeration.
- If you've made 5 or more calls to the same index in a single turn, stop. Explain the limitation and suggest alternatives.

Critical: distinguish "no results" from "query failed":
- "no results" means the index returned nothing — this is real evidence of absence.
- A 402 or 403 means the index is a tier coverage gap — it is NOT evidence of absence. Say so explicitly.
- Never present a tier gate as a negative finding.`

const (
	toolSearchDocs     = "search_docs"
	toolFetchPage      = "fetch_page"
	toolKEVLookup      = "kev_lookup"
	toolCVEExploits    = "cve_exploits"
	toolDetectRules    = "detection_rules"
	toolVCQuery        = "vulncheck_query"
	toolWebSearch      = "web_search"
	toolFindVendorCVEs = "find_vendor_cves"
	toolSearchResearch = "search_research"
	toolSearchCPE      = "search_cpe"
	toolIdentify       = "identify"
	toolPURLLookup     = "purl_lookup"
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
	client      openai.Client
	idx         *index.DB
	vc          *vulncheck.Client // nil when no VulnCheck token provided
	brave       *brave.Client     // nil when no Brave API key provided
	hasResearch bool              // true when research:// pages are in the index
	model       string
	log         *slog.Logger
}

// New constructs an agent. vc and br may be nil; their tools are omitted when absent.
// hasResearch should be true when research:// pages have been synced into the DB.
func New(apiKey, baseURL, model string, idx *index.DB, vc *vulncheck.Client, br *brave.Client, hasResearch bool, log *slog.Logger) *Agent {
	client := openai.NewClient(
		option.WithAPIKey(apiKey),
		option.WithBaseURL(baseURL),
	)
	return &Agent{
		client:      client,
		idx:         idx,
		vc:          vc,
		brave:       br,
		hasResearch: hasResearch,
		model:       model,
		log:         log,
	}
}

func (a *Agent) systemPrompt() string {
	p := fmt.Sprintf(
		"Today's date is %s. For queries about recent CVEs, threat disclosures, or events that may postdate your training data, use web_search or find_vendor_cves — do not rely on training knowledge alone.\n\n",
		time.Now().Format("January 2, 2006"),
	) + baseSystemPrompt
	if a.vc != nil {
		p += vcSystemPromptAddendum
	}
	if a.hasResearch {
		p += researchSystemPromptAddendum
	}
	if a.brave != nil {
		p += braveSystemPromptAddendum
	}
	return p
}

// tools returns the tool definitions to pass to the model, conditionally
// including VulnCheck, research, and Brave tools when available.
func (a *Agent) tools() []openai.ChatCompletionToolParam {
	t := docTools()
	if a.vc != nil {
		t = append(t, vcTools()...)
	}
	if a.hasResearch {
		t = append(t, researchTools()...)
	}
	if a.brave != nil {
		t = append(t, braveTools()...)
	}
	return t
}

const researchSystemPromptAddendum = `

You also have access to a research corpus: VulnCheck's vulnerability-research Jupyter notebooks, ingested and indexed as searchable pages. These notebooks contain:
- Trend analysis (trending CVEs, exploitation timelines)
- Dashboard data (KEV stats by year, vendor/product breakdowns)
- Intelligence reports (initial access, ransomware, canary detections, IP intelligence)
- Reserved CVE analysis (reserved-but-exploited, reserved-by-reference-count)

Use search_research when asked about:
- Statistics or trends (e.g. "how many CVEs are in KEV?", "what vendors have the most exploited CVEs?")
- Intelligence summaries that go beyond single CVE lookups
- Questions about VulnCheck's own analysis and research

After search_research returns snippets, use fetch_page with the research:// URL to get the full content.`

const braveSystemPromptAddendum = `

Web search is available via the web_search and find_vendor_cves tools:
- Use find_vendor_cves(vendor, year) when search_cpe is NOT available (no VulnCheck token), or to supplement search_cpe with web context. It searches the web, extracts CVE IDs from results, and optionally enriches them with VulnCheck KEV status. Web-extracted CVE IDs may be misattributed — always cross-check with kev_lookup or cve_exploits before stating a CVE belongs to a specific vendor.
- If search_cpe is available (VulnCheck token present), prefer it for vendor CVE enumeration — it queries structured CPE data and is more accurate than web scraping.
- Use web_search for general research: recent threat disclosures, CVE context not in VulnCheck, news about an incident or threat actor.
- Do NOT use web search as a primary source when VulnCheck already has the answer — prefer VulnCheck data for all KEV, exploitation, and detection queries.
- After finding candidate CVE IDs via web search or find_vendor_cves, enrich them with kev_lookup or cve_exploits where relevant.`

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
				Description: openai.String("Retrieve exploit intelligence for a CVE across all available indices: xdb (community-tier PoC metadata with maturity level), initial-access, botnets, ransomware, threat-actors (paid tier). Only queries indices the token has access to. Use this to distinguish lab PoCs from weaponized exploit modules. Queries run concurrently."),
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
				Name: toolVCQuery,
				Description: openai.String(
					"Query any VulnCheck index directly. Use when the named tools don't cover the question. " +
						"IMPORTANT index semantics: nist-nvd2 and nist-nvd require an exact CVE ID — they do NOT support " +
						"keyword, vendor, or product name search. Only call these with a specific CVE ID you already know. " +
						"Passing a vendor name as the cve parameter will return a 400 error. " +
						"For vendor/product CVE enumeration, use search_cpe instead."),
				Parameters: shared.FunctionParameters{
					"type": "object",
					"properties": map[string]any{
						"index": map[string]any{
							"type":        "string",
							"description": "Index name from the available indices list.",
						},
						"cve": map[string]any{
							"type":        "string",
							"description": "Exact CVE ID to filter by, e.g. 'CVE-2021-44228'. Strict match only — not a keyword or vendor name.",
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
		{
			Function: shared.FunctionDefinitionParam{
				Name:        toolSearchCPE,
				Description: openai.String("Search for CVEs by CPE attributes (vendor, product, version). Use for 'what CVEs exist for vendor X?' questions. Set is_vulnerable=true to restrict to CPEs that are directly vulnerable (recommended). Available on community tier."),
				Parameters: shared.FunctionParameters{
					"type": "object",
					"properties": map[string]any{
						"vendor": map[string]any{
							"type":        "string",
							"description": "Vendor keyword, e.g. 'fortinet', 'opnsense', 'paloaltonetworks'.",
						},
						"product": map[string]any{
							"type":        "string",
							"description": "Product keyword, e.g. 'fortigate', 'pan-os'. Use underscores instead of spaces.",
						},
						"version": map[string]any{
							"type":        "string",
							"description": "Version string. Supports trailing wildcard: '7.2*' matches all 7.2.x versions.",
						},
						"part": map[string]any{
							"type":        "string",
							"enum":        []string{"a", "o", "h"},
							"description": "'a' = application, 'o' = operating system, 'h' = hardware. Omit to search all.",
						},
						"is_vulnerable": map[string]any{
							"type":        "boolean",
							"description": "If true, return only CVEs where the CPE itself is vulnerable (not just mentioned). Recommended.",
						},
					},
				},
			},
		},
		{
			Function: shared.FunctionDefinitionParam{
				Name:        toolIdentify,
				Description: openai.String("Convert a natural-language (vendor, product, version) description into canonical CPE and PURL identifiers. Use this to find the exact vendor/product slug before calling search_cpe when the spelling is uncertain."),
				Parameters: shared.FunctionParameters{
					"type": "object",
					"properties": map[string]any{
						"vendor": map[string]any{
							"type":        "string",
							"description": "Vendor name as the user described it, e.g. 'Palo Alto Networks', 'Microsoft Corporation'.",
						},
						"product": map[string]any{
							"type":        "string",
							"description": "Product name, e.g. 'PAN-OS', 'Office 2016'.",
						},
						"version": map[string]any{
							"type":        "string",
							"description": "Version string, e.g. '10.2.3'. Optional.",
						},
					},
					"required": []string{"vendor", "product"},
				},
			},
		},
		{
			Function: shared.FunctionDefinitionParam{
				Name:        toolPURLLookup,
				Description: openai.String("Look up CVEs and fixed versions for a specific package version using a Package URL (PURL). Use for 'is this package version vulnerable?' questions. Format: pkg:npm/lodash@4.17.20, pkg:pypi/requests@2.28.0, pkg:golang/github.com/foo/bar@v1.2.3. Available on community tier."),
				Parameters: shared.FunctionParameters{
					"type": "object",
					"properties": map[string]any{
						"purl": map[string]any{
							"type":        "string",
							"description": "Package URL string, e.g. 'pkg:npm/lodash@4.17.20'.",
						},
					},
					"required": []string{"purl"},
				},
			},
		},
	}
}

func braveTools() []openai.ChatCompletionToolParam {
	return []openai.ChatCompletionToolParam{
		{
			Function: shared.FunctionDefinitionParam{
				Name:        toolWebSearch,
				Description: openai.String("Search the web via Brave Search. Use for recent CVE disclosures, threat context, news about an incident or threat actor, or any question VulnCheck doesn't have the answer to. Do NOT use when VulnCheck tools already have the answer."),
				Parameters: shared.FunctionParameters{
					"type": "object",
					"properties": map[string]any{
						"query": map[string]any{
							"type":        "string",
							"description": "Search query. Be specific — include vendor/product names, CVE IDs, or threat actor names as relevant.",
						},
						"count": map[string]any{
							"type":        "integer",
							"description": "Number of results to return (default 5, max 10).",
						},
					},
					"required": []string{"query"},
				},
			},
		},
		{
			Function: shared.FunctionDefinitionParam{
				Name: toolFindVendorCVEs,
				Description: openai.String(
					"Find CVEs for a vendor or product by searching the web and extracting CVE IDs from results. " +
						"Optionally enriches each CVE with VulnCheck KEV status. " +
						"Use when search_cpe is not available (no VulnCheck token) or to supplement it with web context. " +
						"NOTE: web-extracted CVE IDs may be misattributed — always verify attribution with kev_lookup or cve_exploits. " +
						"When a VulnCheck token is present, prefer search_cpe for structured, accurate vendor CVE enumeration."),
				Parameters: shared.FunctionParameters{
					"type": "object",
					"properties": map[string]any{
						"vendor": map[string]any{
							"type":        "string",
							"description": "Vendor or product name to search for, e.g. 'OPNsense', 'Fortinet FortiOS', 'Palo Alto GlobalProtect'.",
						},
						"year": map[string]any{
							"type":        "string",
							"description": "Year to focus on, e.g. '2025'. Defaults to the current year.",
						},
					},
					"required": []string{"vendor"},
				},
			},
		},
	}
}

func researchTools() []openai.ChatCompletionToolParam {
	return []openai.ChatCompletionToolParam{
		{
			Function: shared.FunctionDefinitionParam{
				Name: toolSearchResearch,
				Description: openai.String(
					"Full-text search over VulnCheck's vulnerability-research notebooks. " +
						"Use for questions about trends, statistics, dashboard data, and intelligence summaries " +
						"(e.g. 'how many CVEs in KEV?', 'top vendors in initial-access', 'ransomware CVE trends'). " +
						"Returns matching notebook sections with snippets. Follow with fetch_page to get full content."),
				Parameters: shared.FunctionParameters{
					"type": "object",
					"properties": map[string]any{
						"query": map[string]any{
							"type":        "string",
							"description": "Keywords to search for, e.g. 'KEV vendor coverage 2025' or 'canary exploitation detection'.",
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
	}
}

// Run executes the agent loop for one user turn, appending to sess and
// committing the updated history on success. Closes out when done.
func (a *Agent) Run(ctx context.Context, sess *Session, userQuestion string, out chan<- Event) {
	defer close(out)

	// Build the system prompt for this agent configuration and inject the
	// available VulnCheck indices up-front so the model knows what it can
	// query before making tool calls, avoiding reactive 402 discovery.
	messages := sess.snapshot()
	prompt := a.systemPrompt()
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
	sysMsg := openai.SystemMessage(prompt)
	if len(messages) == 0 {
		messages = append(messages, sysMsg)
	} else {
		messages[0] = sysMsg
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
					a.log.Warn("tool error", "tool", tc.Function.Name, "err", err)
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

	case toolWebSearch:
		return a.dispatchWebSearch(ctx, rawArgs)

	case toolFindVendorCVEs:
		return a.dispatchFindVendorCVEs(ctx, rawArgs)

	case toolSearchResearch:
		return a.dispatchSearchResearch(ctx, rawArgs)

	case toolSearchCPE:
		return a.dispatchSearchCPE(ctx, rawArgs)

	case toolIdentify:
		return a.dispatchIdentify(ctx, rawArgs)

	case toolPURLLookup:
		return a.dispatchPURLLookup(ctx, rawArgs)

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

	// xdb is VulnCheck's community-tier exploit database — structured PoC metadata
	// including maturity level (poc/weaponized), tags, and dates. Querying it here
	// gives the agent characterization data (lab PoC vs weaponized module) alongside
	// the paid-tier operational intel indices.
	allIndices := []string{"initial-access", "botnets", "ransomware", "threat-actors", "xdb"}
	params := url.Values{"cve": {args.CVEID}, "limit": {"5"}}

	type indexResult struct {
		name    string
		entries []json.RawMessage
		err     error
	}

	// Filter to only indices this token can reach before allocating goroutines.
	var accessible []string
	for _, idx := range allIndices {
		if a.vc.HasIndex(ctx, idx) {
			accessible = append(accessible, idx)
		}
	}

	results := make([]indexResult, len(accessible))
	var wg sync.WaitGroup
	for i, idx := range accessible {
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
		if r.err != nil || len(r.entries) == 0 {
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

func (a *Agent) dispatchWebSearch(ctx context.Context, rawArgs string) (string, string, error) {
	var args struct {
		Query string `json:"query"`
		Count int    `json:"count"`
	}
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return "", "", fmt.Errorf("parse args: %w", err)
	}
	if args.Count == 0 {
		args.Count = 5
	}

	results, err := a.brave.Search(ctx, args.Query, args.Count)
	if err != nil {
		return "", "", err
	}
	if len(results) == 0 {
		return fmt.Sprintf("No web search results for %q.", args.Query), "no results", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Web search results for %q:\n\n", args.Query))
	for i, r := range results {
		sb.WriteString(fmt.Sprintf("%d. **%s**\n   %s\n   %s\n\n", i+1, r.Title, r.URL, r.Description))
	}
	return sb.String(), fmt.Sprintf("%d results", len(results)), nil
}

func (a *Agent) dispatchFindVendorCVEs(ctx context.Context, rawArgs string) (string, string, error) {
	var args struct {
		Vendor string `json:"vendor"`
		Year   string `json:"year"`
	}
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return "", "", fmt.Errorf("parse args: %w", err)
	}
	if args.Year == "" {
		args.Year = fmt.Sprintf("%d", time.Now().Year())
	}

	// Step 1: web search for candidate CVEs.
	query := fmt.Sprintf("%s CVE %s vulnerability", args.Vendor, args.Year)
	results, err := a.brave.Search(ctx, query, 10)
	if err != nil {
		return "", "", fmt.Errorf("web search: %w", err)
	}

	// Step 2: extract unique CVE IDs from titles and descriptions.
	seen := make(map[string]bool)
	var cveIDs []string
	for _, r := range results {
		for _, id := range cveIDRe.FindAllString(r.Title+" "+r.Description, -1) {
			if !seen[id] {
				seen[id] = true
				cveIDs = append(cveIDs, id)
			}
		}
	}

	if len(cveIDs) == 0 {
		return fmt.Sprintf(
			"No CVE IDs found in web search results for '%s %s'. The search returned %d pages but none contained CVE IDs. "+
				"Try a more specific vendor name, or search https://nvd.nist.gov/vuln/search directly.",
			args.Vendor, args.Year, len(results)),
			"no CVE IDs found in search results", nil
	}
	if len(cveIDs) > 20 {
		cveIDs = cveIDs[:20]
	}

	// Step 3: optionally enrich each CVE with VulnCheck KEV status (concurrent).
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d candidate CVE IDs for %s (%s) via web search:\n\n",
		len(cveIDs), args.Vendor, args.Year))

	if a.vc != nil {
		type kevStatus struct {
			id    string
			inKEV bool
		}
		statuses := make([]kevStatus, len(cveIDs))
		for i, id := range cveIDs {
			statuses[i].id = id
		}
		var wg sync.WaitGroup
		for i, id := range cveIDs {
			wg.Add(1)
			go func(i int, id string) {
				defer wg.Done()
				entries, err := a.vc.QueryIndex(ctx, "vulncheck-kev", url.Values{"cve": {id}})
				if err == nil && len(entries) > 0 {
					statuses[i].inKEV = true
				}
			}(i, id)
		}
		wg.Wait()

		sb.WriteString("| CVE ID | In KEV |\n|---|---|\n")
		for _, s := range statuses {
			kev := "—"
			if s.inKEV {
				kev = "✓ Yes"
			}
			sb.WriteString(fmt.Sprintf("| `%s` | %s |\n", s.id, kev))
		}
	} else {
		for _, id := range cveIDs {
			sb.WriteString(fmt.Sprintf("- `%s`\n", id))
		}
	}

	sb.WriteString(fmt.Sprintf(
		"\nSource: Brave web search for %q. Verify at https://nvd.nist.gov/vuln/search.", query))
	return sb.String(),
		fmt.Sprintf("%d CVEs found for %s %s", len(cveIDs), args.Vendor, args.Year),
		nil
}

func (a *Agent) dispatchSearchResearch(ctx context.Context, rawArgs string) (string, string, error) {
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
	pages, err := a.idx.SearchResearch(ctx, args.Query, args.Limit)
	if err != nil {
		return "", "", fmt.Errorf("search research: %w", err)
	}
	return formatSearchResult(args.Query, pages), fmt.Sprintf("%d research pages", len(pages)), nil
}

func (a *Agent) dispatchSearchCPE(ctx context.Context, rawArgs string) (string, string, error) {
	var args struct {
		Vendor       string `json:"vendor"`
		Product      string `json:"product"`
		Version      string `json:"version"`
		Part         string `json:"part"`
		IsVulnerable bool   `json:"is_vulnerable"`
	}
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return "", "", fmt.Errorf("parse args: %w", err)
	}

	params := url.Values{}
	if args.Vendor != "" {
		params.Set("vendor", args.Vendor)
	}
	if args.Product != "" {
		params.Set("product", args.Product)
	}
	if args.Version != "" {
		params.Set("version", args.Version)
	}
	if args.Part != "" {
		params.Set("part", args.Part)
	}
	if args.IsVulnerable {
		params.Set("isVulnerable", "true")
	}

	results, err := a.vc.SearchCPE(ctx, params)
	if err != nil {
		return "", "", err
	}
	if len(results) == 0 {
		return fmt.Sprintf("No CPE matches found for vendor=%q product=%q.", args.Vendor, args.Product),
			"no matches", nil
	}

	type cpeResult struct {
		CPE  string   `json:"cpe"`
		CVEs []string `json:"cves"`
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("CPE search results (vendor=%q product=%q):\n\n", args.Vendor, args.Product))
	var totalCVEs int
	for _, r := range results {
		var cpe cpeResult
		if err := json.Unmarshal(r, &cpe); err != nil {
			continue
		}
		totalCVEs += len(cpe.CVEs)
		sb.WriteString(fmt.Sprintf("**%s** — %d CVE(s):\n", cpe.CPE, len(cpe.CVEs)))
		for _, id := range cpe.CVEs {
			sb.WriteString(fmt.Sprintf("  - `%s`\n", id))
		}
		sb.WriteString("\n")
	}
	return sb.String(),
		fmt.Sprintf("%d CPE match(es), %d CVE(s) total", len(results), totalCVEs), nil
}

func (a *Agent) dispatchIdentify(ctx context.Context, rawArgs string) (string, string, error) {
	var args struct {
		Vendor  string `json:"vendor"`
		Product string `json:"product"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return "", "", fmt.Errorf("parse args: %w", err)
	}

	results, err := a.vc.Identify(ctx, args.Vendor, args.Product, args.Version)
	if err != nil {
		return "", "", err
	}
	if len(results) == 0 {
		return fmt.Sprintf("No identifier mappings found for %q %q.", args.Vendor, args.Product),
			"no matches", nil
	}

	type identResult struct {
		Identity struct {
			Vendor  string `json:"vendor"`
			Product string `json:"product"`
			Version string `json:"version"`
		} `json:"identity"`
		Normalized struct {
			Title   string `json:"title"`
			Version string `json:"version"`
		} `json:"normalized"`
		Identifiers struct {
			CPE []struct {
				Value      string `json:"value"`
				Confidence struct {
					Level string `json:"level"`
				} `json:"confidence"`
			} `json:"cpe"`
			PURL []struct {
				Value string `json:"value"`
			} `json:"purl"`
		} `json:"identifiers"`
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Identifier mappings for %q %q:\n\n", args.Vendor, args.Product))
	for _, r := range results {
		var m identResult
		if err := json.Unmarshal(r, &m); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("**%s**\n", m.Normalized.Title))
		for _, c := range m.Identifiers.CPE {
			sb.WriteString(fmt.Sprintf("  CPE: `%s` (confidence: %s)\n", c.Value, c.Confidence.Level))
		}
		for _, p := range m.Identifiers.PURL {
			sb.WriteString(fmt.Sprintf("  PURL: `%s`\n", p.Value))
		}
		sb.WriteString("\n")
	}
	return sb.String(), fmt.Sprintf("%d mapping(s)", len(results)), nil
}

func (a *Agent) dispatchPURLLookup(ctx context.Context, rawArgs string) (string, string, error) {
	var args struct {
		PURL string `json:"purl"`
	}
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return "", "", fmt.Errorf("parse args: %w", err)
	}

	data, err := a.vc.PURLLookup(ctx, args.PURL)
	if err != nil {
		return "", "", err
	}

	var result struct {
		CVEs            []string `json:"cves"`
		Vulnerabilities []struct {
			Detection    string `json:"detection"`
			FixedVersion string `json:"fixed_version"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", "", fmt.Errorf("parse purl data: %w", err)
	}
	if len(result.CVEs) == 0 {
		return fmt.Sprintf("No known vulnerabilities for `%s`.", args.PURL), "no vulnerabilities", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Vulnerabilities for `%s`:\n\n", args.PURL))
	for _, v := range result.Vulnerabilities {
		if v.FixedVersion != "" {
			sb.WriteString(fmt.Sprintf("- `%s` — fixed in `%s`\n", v.Detection, v.FixedVersion))
		} else {
			sb.WriteString(fmt.Sprintf("- `%s` — no fixed version recorded\n", v.Detection))
		}
	}
	return sb.String(), fmt.Sprintf("%d CVE(s) for %s", len(result.CVEs), args.PURL), nil
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
