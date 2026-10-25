// Package recon — nuclei integration. Per the architecture decision, nuclei is
// shelled out to as a binary (its in-process API is CLI-shaped and its dependency
// tree is enormous); it stays a `go install` tool rather than a Go library.
package recon

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"github.com/broodforced/cicada/internal/schema"
)

type nucleiResult struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"info"`
}

// NucleiScanInto runs the nuclei binary against target (if installed) and folds
// its findings into result. It is a no-op when nuclei is not on PATH.
func NucleiScanInto(target string, result *schema.ScanResult) {
	path, err := exec.LookPath("nuclei")
	if err != nil {
		return // not installed — skip silently
	}
	url := target
	if !strings.Contains(url, "://") {
		url = "http://" + url
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-u", url, "-silent", "-jsonl", "-nc", "-timeout", "5", "-tags", "tech,misconfig,exposure")
	out, err := cmd.Output()
	if err != nil {
		return // timeout or nuclei error — skip, don't fail the scan
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var nr nucleiResult
		if json.Unmarshal([]byte(line), &nr) != nil {
			continue
		}
		sev := nr.Info.Severity
		if sev == "" {
			sev = "info"
		}
		result.AddFinding(schema.NewFinding(nr.Info.Name, sev, nr.TemplateID, nr.MatchedAt, nr.Info.Description, "nuclei"))
	}
}
