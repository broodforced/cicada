package report

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/broodforced/cicada/internal/schema"
)

func sampleResult() schema.ScanResult {
	r := schema.NewScanResult("example.com", "normal")
	r.AddSubdomain("www.example.com")
	r.AddSubdomain("api.example.com")
	r.Recon.Assets = append(r.Recon.Assets, schema.Asset{
		Host: "www.example.com", IP: "104.20.23.154", StatusCode: 200,
		Title: "Example Domain", Technologies: []string{"cloudflare"}, CDN: true,
	})
	r.AddEndpoint("https://www.example.com/login")
	secret, _ := json.Marshal(map[string]string{"type": "api-key", "file": "config.js", "match": "AIzaSy..."})
	r.Recon.Secrets = append(r.Recon.Secrets, secret)
	r.AddFinding(schema.NewFinding(
		"Missing HSTS Header", "medium", "security-headers", "https://www.example.com",
		"strict-transport-security header not set", "cicada"))
	return r
}

func TestGenerateWritesHTML(t *testing.T) {
	r := sampleResult()
	out := t.TempDir() + "/report.html"
	if err := Generate(r, out); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	html := string(data)

	for _, want := range []string{
		"<!DOCTYPE html>",
		"<title>cicada — example.com</title>",
		"Missing HSTS Header",
		"strict-transport-security header not set", // detail, as-is
		"MEDIUM", // severity badge, uppercased
		"SECRET",
		"api-key",
		"www.example.com",
		"finding-ref",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report missing %q", want)
		}
	}
	// sanity: no raw unescaped angle brackets leak from the title
	if strings.Contains(html, "<title>") && strings.Count(html, "<title>") != 1 {
		t.Errorf("unexpected title tags")
	}
}

func TestGenerateBatchFiltersSeverity(t *testing.T) {
	r := sampleResult()
	r.AddFinding(schema.NewFinding("Low thing", "low", "misc", "t", "d", "x"))
	reports := GenerateBatch(r.Findings)
	if len(reports) != 1 {
		t.Fatalf("GenerateBatch len = %d, want 1 (only medium is actionable)", len(reports))
	}
	if !strings.Contains(reports[0].Report, "# Steps to Reproduce") {
		t.Errorf("report missing steps section")
	}
}