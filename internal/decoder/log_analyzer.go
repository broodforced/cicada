// Package decoder — log_analyzer scans log text for encoded content and decodes
// it. Go port of decoder/log_analyzer.py.
package decoder

import (
	"fmt"
	"os"
	"regexp"
)

var (
	jwtPattern    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	encodedPattern = regexp.MustCompile(`[A-Za-z0-9+/=]{10,}`)
	urlEncodedPattern = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}){3,}`)
)

// Analyzed is one decoded hit from a log.
type Analyzed struct {
	Encoded string
	Method  string
	Decoded string
}

// Analyze reads a log file and returns every encoded value it can decode.
func Analyze(logfile string) []Analyzed {
	text, err := os.ReadFile(logfile)
	if err != nil {
		return nil
	}
	s := string(text)
	var out []Analyzed
	seen := map[string]bool{}

	for _, m := range jwtPattern.FindAllString(s, -1) {
		if seen[m] {
			continue
		}
		seen[m] = true
		if j := JWTDecode(m); j != nil {
			out = append(out, Analyzed{
				Encoded: truncate(m, 60),
				Method:  "jwt",
				Decoded: fmt.Sprintf("header: %s\npayload: %s", j["header"], j["payload"]),
			})
		}
	}

	for _, m := range encodedPattern.FindAllString(s, -1) {
		if seen[m] {
			continue
		}
		seen[m] = true
		for _, r := range AutoDecode(m) {
			if r.Method == "jwt" {
				continue
			}
			out = append(out, Analyzed{Encoded: m, Method: r.Method, Decoded: r.Decoded})
		}
	}

	for _, m := range urlEncodedPattern.FindAllString(s, -1) {
		if seen[m] {
			continue
		}
		seen[m] = true
		if d := URLDecode(m); d != m {
			out = append(out, Analyzed{Encoded: m, Method: "url", Decoded: d})
		}
	}

	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// AnalyzeAndPrint prints the results in cicada's log-analysis format.
func AnalyzeAndPrint(logfile string) []Analyzed {
	results := Analyze(logfile)
	if len(results) == 0 {
		fmt.Println("[*] No encoded values found.")
		return results
	}
	for _, r := range results {
		fmt.Printf("\n[+] Encoded: %s\n", r.Encoded)
		fmt.Printf("    [%s] %s\n", r.Method, r.Decoded)
	}
	return results
}