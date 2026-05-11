package research

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimalNotebook builds a minimal nbformat v4 JSON string with the given cells.
// Each cell is already a valid JSON object string.
func minimalNotebook(cells ...string) string {
	return `{"nbformat":4,"cells":[` + strings.Join(cells, ",") + `]}`
}

func markdownCell(source string) string {
	b, _ := marshalJSONString(source)
	return `{"cell_type":"markdown","source":` + b + `,"outputs":[]}`
}

func codeCell(outputs ...string) string {
	return `{"cell_type":"code","source":"","outputs":[` + strings.Join(outputs, ",") + `]}`
}

func htmlOutput(html string) string {
	b, _ := marshalJSONString(html)
	return `{"output_type":"execute_result","data":{"text/html":` + b + `}}`
}

func plotlyOutput(layoutTitle, traceType string, labels []string) string {
	lblJSON := `["` + strings.Join(labels, `","`) + `"]`
	return `{"output_type":"display_data","data":{"application/vnd.plotly.v1+json":{` +
		`"layout":{"title":{"text":"` + layoutTitle + `"}},` +
		`"data":[{"type":"` + traceType + `","name":"","labels":` + lblJSON + `}]}}}`
}

// marshalJSONString produces a JSON-quoted string (handles double-quotes inside).
func marshalJSONString(s string) (string, error) {
	import_json := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`)
	return `"` + import_json.Replace(s) + `"`, nil
}

func writeNotebook(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write notebook: %v", err)
	}
	return path
}

// TestJoinSource verifies that both []string and string source fields are handled.
func TestJoinSource(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"array", `["line one\n","line two"]`, "line one\nline two"},
		{"string", `"single line"`, "single line"},
		{"empty array", `[]`, ""},
		{"empty string", `""`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := joinSource([]byte(tc.raw))
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestHTMLTableToMarkdown checks that a pandas-style table becomes pipe rows.
func TestHTMLTableToMarkdown(t *testing.T) {
	html := `<table>
  <thead><tr><th>CVE</th><th>Score</th></tr></thead>
  <tbody>
    <tr><td>CVE-2024-1234</td><td>9.8</td></tr>
    <tr><td>CVE-2024-5678</td><td>7.5</td></tr>
  </tbody>
</table>`

	got := htmlTableToMarkdown(html)

	if !strings.Contains(got, "CVE") {
		t.Error("header row missing")
	}
	if !strings.Contains(got, "CVE-2024-1234") {
		t.Error("data row 1 missing")
	}
	if !strings.Contains(got, "CVE-2024-5678") {
		t.Error("data row 2 missing")
	}
	if !strings.Contains(got, "9.8") {
		t.Error("score value missing")
	}
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 rows (header + 2 data), got %d", len(lines))
	}
}

// TestHTMLTableToMarkdownEmpty returns empty string when there are no <tr> elements.
func TestHTMLTableToMarkdownEmpty(t *testing.T) {
	got := htmlTableToMarkdown("<div>no table here</div>")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// TestParsePlotlyTitle handles both plain string and {"text": ...} title formats.
func TestParsePlotlyTitle(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"string title", `"KEV Dashboard 2025"`, "KEV Dashboard 2025"},
		{"object title", `{"text":"Known Exploited Vulnerabilities","font":{"size":20}}`, "Known Exploited Vulnerabilities"},
		{"empty", `""`, ""},
		{"null", `null`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePlotlyTitle([]byte(tc.raw))
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestToTitle checks directory name → breadcrumb label conversion.
func TestToTitle(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"initial-access", "Initial Access"},
		{"known-exploited-vulnerabilities", "Known Exploited Vulnerabilities"},
		{"nist-nvd", "Nist Nvd"},
		{"ip-intelligence", "Ip Intelligence"},
	}
	for _, tc := range cases {
		got := toTitle(tc.in)
		if got != tc.want {
			t.Errorf("toTitle(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestParseFile_MarkdownTitle checks that the first heading becomes the page title.
func TestParseFile_MarkdownTitle(t *testing.T) {
	nb := minimalNotebook(
		markdownCell("# Initial Access Intelligence (IAI)\n\n## Initial Configuration"),
		markdownCell("Some prose about the product."),
	)
	path := writeNotebook(t, t.TempDir(), "initial-access.ipynb", nb)

	page, err := ParseFile(path, "initial-access/initial-access.ipynb")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if page.Title != "Initial Access Intelligence (IAI)" {
		t.Errorf("title: got %q, want %q", page.Title, "Initial Access Intelligence (IAI)")
	}
	if page.URL != "research://initial-access/initial-access.ipynb" {
		t.Errorf("url: got %q", page.URL)
	}
	if page.Breadcrumb != "Research / Initial Access" {
		t.Errorf("breadcrumb: got %q", page.Breadcrumb)
	}
}

// TestParseFile_H2FallbackTitle checks that ## is used as title when no # exists.
func TestParseFile_H2FallbackTitle(t *testing.T) {
	nb := minimalNotebook(
		codeCell(), // code cell first, no H1 anywhere
		markdownCell("## Reserved But Exploited CVEs\n\nSome description."),
	)
	path := writeNotebook(t, t.TempDir(), "reserved-but-exploited.ipynb", nb)

	page, err := ParseFile(path, "reserved-cves/reserved-but-exploited.ipynb")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if page.Title != "Reserved But Exploited CVEs" {
		t.Errorf("title: got %q, want %q", page.Title, "Reserved But Exploited CVEs")
	}
}

// TestParseFile_FallbackToFilename checks that the filename is used when no heading exists.
func TestParseFile_FallbackToFilename(t *testing.T) {
	nb := minimalNotebook(codeCell())
	path := writeNotebook(t, t.TempDir(), "unnamed.ipynb", nb)

	page, err := ParseFile(path, "unnamed.ipynb")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if page.Title != "unnamed.ipynb" {
		t.Errorf("title: got %q, want filename fallback", page.Title)
	}
}

// TestParseFile_HTMLTableExtracted checks that HTML tables become searchable text.
func TestParseFile_HTMLTableExtracted(t *testing.T) {
	tableHTML := `<table><thead><tr><th>Metric</th><th>Count</th></tr></thead>` +
		`<tbody><tr><td>CVEs in IAI</td><td>849</td></tr>` +
		`<tr><td>Exploits in IAI</td><td>576</td></tr></tbody></table>`

	nb := minimalNotebook(
		markdownCell("# Stats\n"),
		codeCell(htmlOutput(tableHTML)),
	)
	path := writeNotebook(t, t.TempDir(), "stats.ipynb", nb)

	page, err := ParseFile(path, "stats.ipynb")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if !strings.Contains(page.Content, "CVEs in IAI") {
		t.Error("table row 'CVEs in IAI' not found in content")
	}
	if !strings.Contains(page.Content, "849") {
		t.Error("table value '849' not found in content")
	}
}

// TestParseFile_PlotlyTitleExtracted checks that Plotly chart titles are indexed.
func TestParseFile_PlotlyTitleExtracted(t *testing.T) {
	nb := minimalNotebook(
		markdownCell("# Dashboard\n"),
		codeCell(plotlyOutput(
			"Known Exploited Vulnerabilities by Vendor - 2025",
			"treemap",
			[]string{"Apache", "Microsoft", "Fortinet"},
		)),
	)
	path := writeNotebook(t, t.TempDir(), "kev.ipynb", nb)

	page, err := ParseFile(path, "known-exploited-vulnerabilities/kev.ipynb")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if !strings.Contains(page.Content, "Known Exploited Vulnerabilities by Vendor") {
		t.Error("Plotly chart title not found in content")
	}
	if !strings.Contains(page.Content, "Apache") {
		t.Error("Plotly label 'Apache' not found in content")
	}
	if !strings.Contains(page.Content, "Microsoft") {
		t.Error("Plotly label 'Microsoft' not found in content")
	}
}

// TestParseFile_BinaryPlotlyValuesSkipped checks that binary-encoded numeric data
// (the bdata format) doesn't cause a parse error and is silently skipped.
func TestParseFile_BinaryPlotlyValuesSkipped(t *testing.T) {
	nb := `{"nbformat":4,"cells":[{"cell_type":"code","source":"","outputs":[` +
		`{"output_type":"display_data","data":{"application/vnd.plotly.v1+json":{` +
		`"layout":{"title":{"text":"Binary Test Chart"}},` +
		`"data":[{"type":"bar","labels":["A","B","C"],` +
		`"values":{"bdata":"AAAAAAAA8D8=","dtype":"f8"}}]}}}]}]}`

	path := writeNotebook(t, t.TempDir(), "binary.ipynb", nb)

	page, err := ParseFile(path, "binary.ipynb")
	if err != nil {
		t.Fatalf("ParseFile returned error on binary values: %v", err)
	}
	if !strings.Contains(page.Content, "Binary Test Chart") {
		t.Error("chart title not extracted despite binary values field")
	}
	if !strings.Contains(page.Content, "A") {
		t.Error("string labels not extracted alongside binary values")
	}
}

// TestWalk finds all non-checkpoint .ipynb files under a directory.
func TestWalk(t *testing.T) {
	root := t.TempDir()

	// Create a typical directory layout.
	dirs := []string{
		filepath.Join(root, "initial-access"),
		filepath.Join(root, "known-exploited-vulnerabilities"),
		filepath.Join(root, ".ipynb_checkpoints"),
		filepath.Join(root, "known-exploited-vulnerabilities", ".ipynb_checkpoints"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	nb := minimalNotebook(markdownCell("# Test\n"))

	writeNotebook(t, root, "home.ipynb", nb)
	writeNotebook(t, filepath.Join(root, "initial-access"), "initial-access.ipynb", nb)
	writeNotebook(t, filepath.Join(root, "known-exploited-vulnerabilities"), "2025-dashboard.ipynb", nb)
	// These should be skipped:
	writeNotebook(t, filepath.Join(root, ".ipynb_checkpoints"), "home-checkpoint.ipynb", nb)
	writeNotebook(t, filepath.Join(root, "known-exploited-vulnerabilities", ".ipynb_checkpoints"), "2025-checkpoint.ipynb", nb)

	pages, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(pages) != 3 {
		t.Errorf("expected 3 pages (checkpoints excluded), got %d", len(pages))
		for _, p := range pages {
			t.Logf("  %s", p.URL)
		}
	}
	for _, p := range pages {
		if strings.Contains(p.URL, "checkpoint") {
			t.Errorf("checkpoint file was not excluded: %s", p.URL)
		}
	}
}
