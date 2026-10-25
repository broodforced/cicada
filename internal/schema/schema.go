// Package schema defines the JSON data contract shared between cicada and tymbal.
// This is the Go port of shared/schema.py — the field names and shapes must stay
// identical so tymbal output and cicada output merge cleanly.
package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Evidence captures proof for a finding.
type Evidence struct {
	Request    string `json:"request"`
	Response   string `json:"response"`
	Screenshot string `json:"screenshot"`
	Timestamp  string `json:"timestamp"`
}

// Finding is one detected issue.
type Finding struct {
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Category   string   `json:"category"`
	Target     string   `json:"target"`
	Detail     string   `json:"detail"`
	Evidence   Evidence `json:"evidence"`
	Tool       string   `json:"tool"`
	Confidence string   `json:"confidence"`
	Reference  string   `json:"reference"`
	FindingID  string   `json:"finding_id"`
}

// NewFinding builds a Finding and derives its stable id from title+target+detail.
func NewFinding(title, severity, category, target, detail, tool string) Finding {
	raw := title + target + detail
	sum := sha256.Sum256([]byte(raw))
	return Finding{
		Title:      title,
		Severity:   severity,
		Category:   category,
		Target:     target,
		Detail:     detail,
		Tool:       tool,
		Confidence: "medium",
		FindingID:  hex.EncodeToString(sum[:])[:12],
		Evidence:   Evidence{Timestamp: time.Now().UTC().Format(time.RFC3339)},
	}
}

// Asset is one reachable host with what we learned about it.
type Asset struct {
	Host          string   `json:"host"`
	IP            string   `json:"ip"`
	Ports         []int    `json:"ports"`
	Technologies  []string `json:"technologies"`
	StatusCode    int      `json:"status_code"`
	ContentLength int      `json:"content_length"`
	Title         string   `json:"title"`
	CDN           bool     `json:"cdn"`
	Source        string   `json:"source"`
}

// ReconData holds the gathered intelligence for a target.
type ReconData struct {
	Target     string            `json:"target"`
	Subdomains []string          `json:"subdomains"`
	Assets     []Asset           `json:"assets"`
	Endpoints  []string          `json:"endpoints"`
	JSFiles    []string          `json:"js_files"`
	Parameters []string          `json:"parameters"`
	Secrets    []json.RawMessage `json:"secrets"`
	Timestamp  string            `json:"timestamp"`
}

// Merge folds another ReconData's results into this one, deduplicating by value.
func (r *ReconData) Merge(other ReconData) {
	r.Subdomains = union(r.Subdomains, other.Subdomains)
	r.Endpoints = union(r.Endpoints, other.Endpoints)
	r.JSFiles = union(r.JSFiles, other.JSFiles)
	r.Parameters = union(r.Parameters, other.Parameters)

	seenSecrets := map[string]bool{}
	for _, s := range r.Secrets {
		seenSecrets[string(s)] = true
	}
	for _, s := range other.Secrets {
		if !seenSecrets[string(s)] {
			r.Secrets = append(r.Secrets, s)
			seenSecrets[string(s)] = true
		}
	}

	knownHosts := map[string]bool{}
	for _, a := range r.Assets {
		knownHosts[a.Host] = true
	}
	for _, a := range other.Assets {
		if !knownHosts[a.Host] {
			r.Assets = append(r.Assets, a)
			knownHosts[a.Host] = true
		}
	}
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	out := a[:0]
	for _, s := range a {
		if !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
	}
	for _, s := range b {
		if !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
	}
	return out
}

// ScanResult is the top-level document cicada (and tymbal) write out.
type ScanResult struct {
	Target   string    `json:"target"`
	Tool     string    `json:"tool"`
	Version  string    `json:"version"`
	Recon    ReconData `json:"recon"`
	Findings []Finding `json:"findings"`
	Started  string    `json:"started"`
	Finished string    `json:"finished"`
	Mode     string    `json:"mode"`
	Scope    []string  `json:"scope"`
}

func NewScanResult(target, mode string) ScanResult {
	now := time.Now().UTC().Format(time.RFC3339)
	return ScanResult{
		Target:  target,
		Tool:    "cicada",
		Version: "0.1.0",
		Mode:    mode,
		Started: now,
		Recon: ReconData{
			Target:     target,
			Subdomains: []string{},
			Assets:     []Asset{},
			Endpoints:  []string{},
			JSFiles:    []string{},
			Parameters: []string{},
			Secrets:    []json.RawMessage{},
			Timestamp:  now,
		},
		Findings: []Finding{},
		Scope:    []string{},
	}
}

func (s *ScanResult) Finish() {
	s.Finished = time.Now().UTC().Format(time.RFC3339)
}

func (s *ScanResult) AddFinding(f Finding) {
	for _, e := range s.Findings {
		if e.FindingID == f.FindingID {
			return
		}
	}
	s.Findings = append(s.Findings, f)
}

func (s *ScanResult) AddSubdomain(sub string) {
	for _, e := range s.Recon.Subdomains {
		if e == sub {
			return
		}
	}
	s.Recon.Subdomains = append(s.Recon.Subdomains, sub)
}

func (s *ScanResult) AddAsset(a Asset) {
	for _, e := range s.Recon.Assets {
		if e.Host == a.Host {
			return
		}
	}
	s.Recon.Assets = append(s.Recon.Assets, a)
}

func (s *ScanResult) AddEndpoint(ep string) {
	for _, e := range s.Recon.Endpoints {
		if e == ep {
			return
		}
	}
	s.Recon.Endpoints = append(s.Recon.Endpoints, ep)
}

func (s *ScanResult) WriteJSON(path string) error {
	data, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func LoadJSON(path string) (ScanResult, error) {
	var r ScanResult
	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return r, err
	}
	return r, nil
}

// Summary is the one-line human result, matching cicada's Python summary wording.
func (s *ScanResult) Summary() string {
	sev := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range s.Findings {
		sev[strings.ToLower(f.Severity)]++
	}
	parts := make([]string, 0, 5)
	for _, k := range []string{"critical", "high", "medium", "low", "info"} {
		if sev[k] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", sev[k], k))
		}
	}
	rest := "none"
	if len(parts) > 0 {
		rest = strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%d subdomains | %d live hosts | %d endpoints | findings: %s",
		len(s.Recon.Subdomains), len(s.Recon.Assets), len(s.Recon.Endpoints), rest)
}