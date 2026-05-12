// Package research parses Jupyter notebooks (.ipynb) and extracts text content
// for indexing in the docs FTS store.
package research

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Page is the extracted, indexable content from one notebook.
type Page struct {
	// URL uses the scheme research://<relative-path> so it's distinguishable
	// from scraped docs pages in the same SQLite table.
	URL        string
	Title      string
	Breadcrumb string
	Content    string
}

// notebook is the nbformat v4 top-level structure.
type notebook struct {
	Cells []cell `json:"cells"`
}

type cell struct {
	CellType string          `json:"cell_type"`
	Source   json.RawMessage `json:"source"` // string or []string
	Outputs  []cellOutput    `json:"outputs"`
}

type cellOutput struct {
	OutputType string                     `json:"output_type"`
	Data       map[string]json.RawMessage `json:"data"`
	Text       json.RawMessage            `json:"text"` // for stream outputs
}

var (
	rowRe  = regexp.MustCompile(`(?is)<tr[^>]*>(.*?)</tr>`)
	cellRe = regexp.MustCompile(`(?is)<t[hd][^>]*>(.*?)</t[hd]>`)
	tagRe  = regexp.MustCompile(`<[^>]+>`)
	headingRe = regexp.MustCompile(`(?m)^#{1,3}\s+(.+)$`)
)

// ParseFile reads a .ipynb file and returns an indexable Page.
// relPath is relative to the research root, used to build the URL and breadcrumb.
func ParseFile(fsPath, relPath string) (*Page, error) {
	data, err := os.ReadFile(fsPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", fsPath, err)
	}

	var nb notebook
	if err := json.Unmarshal(data, &nb); err != nil {
		return nil, fmt.Errorf("parse %s: %w", fsPath, err)
	}

	content := extractText(nb)

	// Derive title from the first markdown heading only — code cells also
	// start with '#' comments and would produce wrong titles if we searched
	// the full concatenated content.
	title := filepath.Base(relPath)
	for _, c := range nb.Cells {
		if c.CellType != "markdown" {
			continue
		}
		if m := headingRe.FindStringSubmatch(joinSource(c.Source)); m != nil {
			title = strings.TrimSpace(m[1])
			break
		}
	}

	// Breadcrumb: "Research / <directory>"
	dir := filepath.Dir(relPath)
	if dir == "." {
		dir = ""
	}
	breadcrumb := "Research"
	if dir != "" {
		breadcrumb += " / " + toTitle(dir)
	}

	return &Page{
		URL:        "research://" + filepath.ToSlash(relPath),
		Title:      title,
		Breadcrumb: breadcrumb,
		Content:    content,
	}, nil
}

// extractText converts notebook cells to a plain-text/markdown document.
func extractText(nb notebook) string {
	var sb strings.Builder
	for _, c := range nb.Cells {
		src := joinSource(c.Source)
		switch c.CellType {
		case "markdown":
			sb.WriteString(src)
			sb.WriteString("\n\n")
		case "code":
			// Index source so that chart titles, column names, and comments
			// buried in code cells (especially matplotlib charts that produce
			// opaque PNG outputs) are reachable by keyword search.
			if src != "" {
				sb.WriteString(src)
				sb.WriteString("\n\n")
			}
			for _, o := range c.Outputs {
				if html, ok := extractHTML(o); ok {
					if md := htmlTableToMarkdown(html); md != "" {
						sb.WriteString(md)
						sb.WriteString("\n\n")
					}
				}
				if title, labels := extractPlotly(o); title != "" || len(labels) > 0 {
					if title != "" {
						sb.WriteString("Chart: ")
						sb.WriteString(title)
						sb.WriteString("\n")
					}
					if len(labels) > 0 {
						n := len(labels)
						if n > 30 {
							n = 30
						}
						sb.WriteString("Categories: ")
						sb.WriteString(strings.Join(labels[:n], ", "))
						sb.WriteString("\n\n")
					}
				}
				if text := extractTextOutput(o); text != "" {
					sb.WriteString(text)
					sb.WriteString("\n\n")
				}
			}
		}
	}
	return strings.TrimSpace(sb.String())
}

// joinSource handles both string and []string source fields in nbformat.
func joinSource(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// Try []string first (most common).
	var lines []string
	if err := json.Unmarshal(raw, &lines); err == nil {
		return strings.Join(lines, "")
	}
	// Fallback: single string.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return ""
}

// extractTextOutput returns printable text from stream (stdout/stderr) and
// execute_result/display_data text/plain outputs. Skips Python repr strings
// like "<pandas.io.formats.style.Styler at 0x...>" which add no signal.
func extractTextOutput(o cellOutput) string {
	var raw json.RawMessage
	if o.OutputType == "stream" {
		raw = o.Text
	} else if o.OutputType == "execute_result" || o.OutputType == "display_data" {
		raw = o.Data["text/plain"]
	}
	if len(raw) == 0 {
		return ""
	}
	text := strings.TrimSpace(joinSource(raw))
	if strings.HasPrefix(text, "<") {
		return "" // skip repr strings
	}
	return text
}

// extractHTML returns the text/html mime content if the output contains it.
func extractHTML(o cellOutput) (string, bool) {
	raw, ok := o.Data["text/html"]
	if !ok {
		return "", false
	}
	return joinSource(raw), true
}

// htmlTableToMarkdown converts a pandas-style HTML table to plain text rows.
// Each row becomes a pipe-separated line; this is enough for FTS indexing.
func htmlTableToMarkdown(htmlStr string) string {
	rows := rowRe.FindAllStringSubmatch(htmlStr, -1)
	if len(rows) == 0 {
		return ""
	}
	var lines []string
	for _, row := range rows {
		cells := cellRe.FindAllStringSubmatch(row[1], -1)
		var cols []string
		for _, c := range cells {
			text := tagRe.ReplaceAllString(c[1], "")
			text = html.UnescapeString(text)
			text = strings.Join(strings.Fields(text), " ") // collapse whitespace
			if text == "" {
				text = "—"
			}
			cols = append(cols, text)
		}
		if len(cols) > 0 {
			lines = append(lines, strings.Join(cols, " | "))
		}
	}
	return strings.Join(lines, "\n")
}

// plotlyLayout captures the fields we care about from a Plotly layout.
type plotlyLayout struct {
	Title json.RawMessage `json:"title"` // string or {text: string}
	XAxis struct {
		Title json.RawMessage `json:"title"`
	} `json:"xaxis"`
	YAxis struct {
		Title json.RawMessage `json:"title"`
	} `json:"yaxis"`
}

// plotlyTrace captures the fields we care about from a Plotly trace.
type plotlyTrace struct {
	Type   string          `json:"type"`
	Name   string          `json:"name"`
	Labels json.RawMessage `json:"labels"` // []string or binary dict — handle both
}

// plotlyDoc is the top-level Plotly JSON object.
type plotlyDoc struct {
	Layout plotlyLayout  `json:"layout"`
	Data   []plotlyTrace `json:"data"`
}

// extractPlotly returns the chart title and category labels from a Plotly output.
func extractPlotly(o cellOutput) (title string, labels []string) {
	raw, ok := o.Data["application/vnd.plotly.v1+json"]
	if !ok {
		return "", nil
	}

	var doc plotlyDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", nil
	}

	title = parsePlotlyTitle(doc.Layout.Title)

	for _, trace := range doc.Data {
		// Labels are plain string arrays in treemap/bar; skip binary-encoded numeric data.
		var lbls []string
		if err := json.Unmarshal(trace.Labels, &lbls); err == nil && len(lbls) > 0 {
			labels = append(labels, lbls...)
		}
		// Also capture trace name as a label if non-empty.
		if trace.Name != "" {
			labels = append(labels, trace.Name)
		}
	}
	return title, labels
}

// parsePlotlyTitle handles both string and {text: string} title formats.
func parsePlotlyTitle(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// Try string first.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Try object with "text" field.
	var obj struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.Text
	}
	return ""
}

// toTitle converts a dash/underscore filename segment to a title-cased label.
func toTitle(s string) string {
	s = strings.ReplaceAll(s, "-", " ")
	s = strings.ReplaceAll(s, "_", " ")
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// Walk returns all indexable Pages found under rootDir.
// rootDir should be the path to the vulnerability-research checkout.
func Walk(rootDir string) ([]*Page, error) {
	var pages []*Page
	err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip hidden dirs and Python cache dirs.
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".ipynb") {
			return nil
		}
		// Skip checkpoint files.
		if strings.Contains(path, ".ipynb_checkpoints") {
			return nil
		}
		rel, err := filepath.Rel(rootDir, path)
		if err != nil {
			return fmt.Errorf("rel path: %w", err)
		}
		page, err := ParseFile(path, rel)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		pages = append(pages, page)
		return nil
	})
	return pages, err
}
