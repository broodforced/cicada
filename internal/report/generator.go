// Package report renders cicada's findings as a single-file dark HTML report.
// Go port of report/generator.py.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"sort"
	"strings"

	"github.com/broodforced/cicada/internal/schema"
)

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
var sevColor = map[string]string{
	"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706",
	"low": "#2563eb", "info": "#6b7280",
}

func rankOf(s string) int {
	if r, ok := sevRank[strings.ToLower(s)]; ok {
		return r
	}
	return 5
}
func colorOf(s string) string {
	if c, ok := sevColor[strings.ToLower(s)]; ok {
		return c
	}
	return "#6b7280"
}
func esc(v string) string { return html.EscapeString(v) }

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

type secretView struct {
	Type  string `json:"type"`
	File  string `json:"file"`
	Match string `json:"match"`
}

// Generate writes a self-contained dark HTML report to outputPath.
func Generate(result schema.ScanResult, outputPath string) error {
	findings := append([]schema.Finding(nil), result.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		return rankOf(findings[i].Severity) < rankOf(findings[j].Severity)
	})

	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range findings {
		counts[strings.ToLower(f.Severity)]++
	}

	body := render(result, findings, counts)
	return os.WriteFile(outputPath, []byte(body), 0o644)
}

func buildFindings(findings []schema.Finding) string {
	var w strings.Builder
	for _, f := range findings {
		color := colorOf(f.Severity)
		evBlock := ""
		if f.Evidence.Request != "" || f.Evidence.Response != "" {
			var parts []string
			if f.Evidence.Request != "" {
				parts = append(parts, fmt.Sprintf(`<div class="ev-section"><span class="ev-label">request</span><pre>%s</pre></div>`, esc(f.Evidence.Request)))
			}
			if f.Evidence.Response != "" {
				parts = append(parts, fmt.Sprintf(`<div class="ev-section"><span class="ev-label">response</span><pre>%s</pre></div>`, esc(trunc(f.Evidence.Response, 1500))))
			}
			evBlock = fmt.Sprintf(`<details class="ev"><summary>evidence</summary>%s</details>`, strings.Join(parts, ""))
		}
		refBlock := ""
		if f.Reference != "" {
			refBlock = fmt.Sprintf(`<div class="finding-ref">ref: %s</div>`, esc(f.Reference))
		}
		fmt.Fprintf(&w, "<div class=\"finding\">\n"+
			"<div class=\"fh\"><span class=\"sev\" style=\"background:%s\">%s</span><span class=\"ft\">%s</span><span class=\"ftool\">%s</span></div>\n"+
			"<div class=\"ftarget\">%s</div>\n"+
			"<div class=\"fdetail\">%s</div>\n"+
			"%s%s</div>\n",
			color, esc(strings.ToUpper(f.Severity)), esc(f.Title), esc(f.Tool),
			esc(f.Target), esc(f.Detail), refBlock, evBlock)
	}
	return w.String()
}

func buildAssets(result schema.ScanResult) string {
	var w strings.Builder
	assets := result.Recon.Assets
	if len(assets) > 200 {
		assets = assets[:200]
	}
	for _, a := range assets {
		tech := ""
		if t := a.Technologies; len(t) > 0 {
			if len(t) > 5 {
				t = t[:5]
			}
			tech = strings.Join(t, ", ")
		}
		cdn := ""
		if a.CDN {
			cdn = "CDN"
		}
		status := ""
		if a.StatusCode != 0 {
			status = fmt.Sprintf("%d", a.StatusCode)
		}
		fmt.Fprintf(&w, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			esc(a.Host), status, esc(a.Title), esc(tech), cdn)
	}
	return w.String()
}

func buildEndpoints(result schema.ScanResult) string {
	var w strings.Builder
	eps := result.Recon.Endpoints
	if len(eps) > 500 {
		eps = eps[:500]
	}
	for _, ep := range eps {
		fmt.Fprintf(&w, "<div class=\"ep\">%s</div>", esc(ep))
	}
	return w.String()
}

func buildSecrets(result schema.ScanResult) string {
	var w strings.Builder
	for _, raw := range result.Recon.Secrets {
		var sv secretView
		if json.Unmarshal(raw, &sv) != nil {
			continue
		}
		fmt.Fprintf(&w, "<div class=\"finding\"><span class=\"sev\" style=\"background:#ea580c\">SECRET</span> <b>%s</b> in %s<br><code class=\"fdetail\">%s</code></div>\n",
			esc(sv.Type), esc(trunc(sv.File, 80)), esc(trunc(sv.Match, 100)))
	}
	return w.String()
}

func render(result schema.ScanResult, findings []schema.Finding, counts map[string]int) string {
	findingHTML := buildFindings(findings)
	assetHTML := buildAssets(result)
	epHTML := buildEndpoints(result)
	secretHTML := buildSecrets(result)

	started := trunc(result.Started, 19)
	finished := trunc(result.Finished, 19)
	r := result.Recon

	var w strings.Builder

	w.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	w.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
	fmt.Fprintf(&w, "<title>cicada — %s</title>\n", esc(result.Target))
	w.WriteString("<style>\n")
	w.WriteString("*{margin:0;padding:0;box-sizing:border-box}\n" +
		":root{--bg:#0a0a0a;--sf:#141414;--bd:#222;--tx:#e0e0e0;--mt:#888;--ac:#22d3ee}\n" +
		"body{background:var(--bg);color:var(--tx);font:14px/1.6 'SF Mono',Monaco,Consolas,monospace;padding:2rem;max-width:1200px;margin:0 auto}\n" +
		"h1{font-size:1.4rem;color:var(--ac);margin-bottom:.25rem}\n" +
		"h2{font-size:1.1rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--bd)}\n" +
		".meta{color:var(--mt);font-size:.85rem;margin-bottom:2rem}\n" +
		".stats{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0 2rem}\n" +
		".stat{background:var(--sf);border:1px solid var(--bd);border-radius:6px;padding:.75rem 1.25rem;text-align:center;min-width:100px}\n" +
		".sv{font-size:1.5rem;font-weight:700}.sl{font-size:.75rem;color:var(--mt);text-transform:uppercase;letter-spacing:.05em}\n" +
		".finding{background:var(--sf);border:1px solid var(--bd);border-radius:6px;padding:1rem;margin-bottom:.75rem}\n" +
		".fh{display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem;flex-wrap:wrap}\n" +
		".sev{color:#fff;font-size:.7rem;font-weight:700;padding:.2rem .5rem;border-radius:3px;letter-spacing:.03em}\n" +
		".ft{font-weight:600;flex:1}.ftool{color:var(--mt);font-size:.8rem}\n" +
		".ftarget{color:var(--ac);font-size:.85rem;margin-bottom:.25rem;word-break:break-all}\n" +
		".fdetail{color:var(--mt);font-size:.85rem}.finding-ref{color:var(--mt);font-size:.8rem;margin-top:.25rem}\n" +
		".ev{margin-top:.5rem}.ev summary{color:var(--ac);font-size:.8rem;cursor:pointer}\n" +
		".ev-section{margin:.5rem 0}.ev-label{font-size:.75rem;color:var(--mt);text-transform:uppercase}\n" +
		".ev pre{background:#0d0d0d;border:1px solid var(--bd);border-radius:4px;padding:.5rem;overflow-x:auto;font-size:.8rem;max-height:300px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}\n" +
		"table{width:100%;border-collapse:collapse;font-size:.85rem}\n" +
		"th,td{text-align:left;padding:.5rem .75rem;border-bottom:1px solid var(--bd)}\n" +
		"th{color:var(--mt);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}\n" +
		"tr:hover td{background:var(--sf)}\n" +
		".ep{font-size:.8rem;color:var(--mt);padding:.15rem 0;word-break:break-all}\n" +
		".empty{color:var(--mt);font-style:italic;padding:1rem}\n")
	w.WriteString("</style>\n</head>\n<body>\n<h1>cicada</h1>\n")

	fmt.Fprintf(&w, "<div class=\"meta\">%s &middot; %s mode &middot; %s &mdash; %s</div>\n\n",
		esc(result.Target), result.Mode, started, finished)

	fmt.Fprintf(&w, "<div class=\"stats\">\n")
	fmt.Fprintf(&w, "<div class=\"stat\"><div class=\"sv\">%d</div><div class=\"sl\">subdomains</div></div>\n", len(r.Subdomains))
	fmt.Fprintf(&w, "<div class=\"stat\"><div class=\"sv\">%d</div><div class=\"sl\">live hosts</div></div>\n", len(r.Assets))
	fmt.Fprintf(&w, "<div class=\"stat\"><div class=\"sv\">%d</div><div class=\"sl\">endpoints</div></div>\n", len(r.Endpoints))
	fmt.Fprintf(&w, "<div class=\"stat\"><div class=\"sv\" style=\"color:#dc2626\">%d</div><div class=\"sl\">critical</div></div>\n", counts["critical"])
	fmt.Fprintf(&w, "<div class=\"stat\"><div class=\"sv\" style=\"color:#ea580c\">%d</div><div class=\"sl\">high</div></div>\n", counts["high"])
	fmt.Fprintf(&w, "<div class=\"stat\"><div class=\"sv\" style=\"color:#d97706\">%d</div><div class=\"sl\">medium</div></div>\n", counts["medium"])
	fmt.Fprintf(&w, "<div class=\"stat\"><div class=\"sv\" style=\"color:#2563eb\">%d</div><div class=\"sl\">low</div></div>\n", counts["low"])
	fmt.Fprintf(&w, "<div class=\"stat\"><div class=\"sv\" style=\"color:#6b7280\">%d</div><div class=\"sl\">info</div></div>\n", counts["info"])
	w.WriteString("</div>\n\n")

	fmt.Fprintf(&w, "<h2>findings (%d)</h2>\n", len(findings))
	if findingHTML == "" {
		w.WriteString("<div class=\"empty\">no findings</div>\n")
	} else {
		w.WriteString(findingHTML)
	}

	fmt.Fprintf(&w, "<h2>live assets (%d)</h2>\n", len(r.Assets))
	w.WriteString("<table><thead><tr><th>host</th><th>status</th><th>title</th><th>tech</th><th>cdn</th></tr></thead>\n<tbody>")
	if assetHTML == "" {
		w.WriteString("<tr><td colspan=\"5\" class=\"empty\">no assets discovered</td></tr>")
	} else {
		w.WriteString(assetHTML)
	}
	w.WriteString("</tbody></table>\n")

	fmt.Fprintf(&w, "<h2>endpoints (%d)</h2>\n", len(r.Endpoints))
	if epHTML == "" {
		w.WriteString("<div class=\"empty\">no endpoints discovered</div>\n")
	} else {
		w.WriteString(epHTML)
	}

	if len(r.Secrets) > 0 {
		fmt.Fprintf(&w, "<h2>secrets (%d)</h2>\n%s", len(r.Secrets), secretHTML)
	}

	w.WriteString("\n</body></html>")
	return w.String()
}