package main

import "testing"

func TestDeriveHumanURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{
			"https://docs.vulncheck.com/raw/getting-started.md",
			"https://docs.vulncheck.com/getting-started",
		},
		{
			"https://docs.vulncheck.com/raw/products/initial-access-intelligence.md",
			"https://docs.vulncheck.com/products/initial-access-intelligence",
		},
		{
			"https://docs.vulncheck.com/raw/tools/go-exploit.md",
			"https://docs.vulncheck.com/tools/go-exploit",
		},
		{
			// no /raw/ prefix — should pass through unchanged except .md strip
			"https://docs.vulncheck.com/products/foo.md",
			"https://docs.vulncheck.com/products/foo",
		},
	}
	for _, tc := range cases {
		got := deriveHumanURL(tc.in)
		if got != tc.want {
			t.Errorf("deriveHumanURL(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
		}
	}
}

func TestBreadcrumbFromURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{
			"https://docs.vulncheck.com/getting-started",
			"Getting Started",
		},
		{
			"https://docs.vulncheck.com/products/initial-access-intelligence",
			"Products > Initial Access Intelligence",
		},
		{
			"https://docs.vulncheck.com/products/initial-access-intelligence/coverage-strategy",
			"Products > Initial Access Intelligence > Coverage Strategy",
		},
		{
			"https://docs.vulncheck.com/tools/go-exploit",
			"Tools > Go Exploit",
		},
		{
			// unrecognised host — should return empty string
			"https://example.com/foo/bar",
			"",
		},
	}
	for _, tc := range cases {
		got := breadcrumbFromURL(tc.in)
		if got != tc.want {
			t.Errorf("breadcrumbFromURL(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
		}
	}
}

func TestTitleCase(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"foo", "Foo"},
		{"initial access intelligence", "Initial Access Intelligence"},
		{"go exploit", "Go Exploit"},
	}
	for _, tc := range cases {
		got := titleCase(tc.in)
		if got != tc.want {
			t.Errorf("titleCase(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
