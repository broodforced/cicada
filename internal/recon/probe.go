// Package recon — HTTP probing and header/CORS checks, native Go (net/http).
// Mirrors tymbal.c's probe behavior: https-then-http, title/server/tech/CDN/IP,
// and the deep-mode security-header + CORS findings.
package recon

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/broodforced/cicada/internal/schema"
)

var probeClient = &http.Client{
	Timeout: 6 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// ProbeHost probes a host over https then http and returns a populated Asset.
// ok is false if neither scheme responded.
func ProbeHost(host string) (schema.Asset, bool) {
	a := schema.Asset{Host: host, Source: "cicada"}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	if ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host); err == nil {
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				a.IP = v4.String()
				break
			}
		}
	}
	cancel()

	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + host
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Cicada/0.1.0")
		resp, err := probeClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		a.StatusCode = resp.StatusCode
		a.ContentLength = int(resp.ContentLength)
		a.Title = extractTitle(string(body))
		if s := resp.Header.Get("Server"); s != "" {
			a.Technologies = append(a.Technologies, s)
		}
		if s := resp.Header.Get("X-Powered-By"); s != "" {
			a.Technologies = append(a.Technologies, s)
		}
		a.CDN = detectCDN(resp.Header)
		if scheme == "https" {
			a.Ports = []int{443}
		} else {
			a.Ports = []int{80}
		}
		return a, true
	}
	return a, false
}

func extractTitle(html string) string {
	lower := strings.ToLower(html)
	i := strings.Index(lower, "<title")
	if i < 0 {
		return ""
	}
	gt := strings.Index(html[i:], ">")
	if gt < 0 {
		return ""
	}
	start := i + gt + 1
	end := strings.Index(html[start:], "<")
	if end < 0 {
		end = len(html) - start
	}
	title := strings.TrimSpace(html[start : start+end])
	if len(title) > 60 {
		title = title[:60]
	}
	return title
}

func detectCDN(h http.Header) bool {
	for _, k := range []string{"Cf-Ray", "X-Cdn", "X-Cache", "X-Amz-Cf-Id"} {
		if h.Get(k) != "" {
			return true
		}
	}
	server := strings.ToLower(h.Get("Server"))
	for _, marker := range []string{"cloudflare", "cloudfront", "akamai", "fastly"} {
		if strings.Contains(server, marker) {
			return true
		}
	}
	return false
}

// HeaderChecks flags missing security headers on a live host.
func HeaderChecks(host string, result *schema.ScanResult) {
	url := "https://" + host
	resp, err := probeClient.Head(url)
	if err != nil {
		return
	}
	resp.Body.Close()
	h := resp.Header
	if h.Get("Strict-Transport-Security") == "" {
		result.AddFinding(schema.NewFinding("Missing HSTS Header", "medium", "security-headers", url, "strict-transport-security header not set", "cicada"))
	}
	if h.Get("X-Content-Type-Options") == "" {
		result.AddFinding(schema.NewFinding("Missing X-Content-Type-Options", "low", "security-headers", url, "x-content-type-options header not set", "cicada"))
	}
	if h.Get("Content-Security-Policy") == "" {
		result.AddFinding(schema.NewFinding("Missing Content-Security-Policy", "low", "security-headers", url, "content-security-policy header not set", "cicada"))
	}
}

// CORS checks for wildcard/reflected origins on a live host.
func CORS(host string, result *schema.ScanResult) {
	url := "https://" + host
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Origin", "https://evil.com")
	resp, err := probeClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	switch acao {
	case "*":
		result.AddFinding(schema.NewFinding("CORS Wildcard Origin", "medium", "cors-misconfiguration", url, "Access-Control-Allow-Origin: *", "cicada"))
	case "https://evil.com":
		sev := "medium"
		if resp.Header.Get("Access-Control-Allow-Credentials") == "true" {
			sev = "high"
		}
		result.AddFinding(schema.NewFinding("CORS Origin Reflection", sev, "cors-misconfiguration", url, "Origin evil.com reflected", "cicada"))
	}
}
