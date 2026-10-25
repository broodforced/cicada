// Package report — request/response capture for evidence. Go port of report/evidence.py.
package report

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/broodforced/cicada/internal/schema"
)

var insecureClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// CaptureRequest performs a request (skipping TLS verification) and captures an
// Evidence{request, response} pair for the finding.
func CaptureRequest(url, method string, headers map[string]string, body string, timeoutSec int) schema.Evidence {
	if headers == nil {
		headers = map[string]string{"User-Agent": "Cicada/0.1.0"}
	}
	reqStr := method + " " + url + "\n"
	for _, k := range sortedKeys(headers) {
		reqStr += k + ": " + headers[k] + "\n"
	}
	if body != "" {
		reqStr += "\n" + body
	}

	respStr := capture(url, method, headers, body, timeoutSec)

	return schema.Evidence{
		Request:  strings.TrimSpace(reqStr),
		Response: strings.TrimSpace(respStr),
	}
}

func capture(url, method string, headers map[string]string, body string, timeoutSec int) string {
	if timeoutSec == 0 {
		timeoutSec = 10
	}
	client := insecureClient
	if timeoutSec != 10 {
		client = &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}

	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return "Error: " + err.Error()
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "Error: " + err.Error()
	}
	defer resp.Body.Close()

	var w strings.Builder
	fmt.Fprintf(&w, "HTTP %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	for _, k := range sortedKeysOfHeader(resp.Header) {
		fmt.Fprintf(&w, "%s: %s\n", k, strings.Join(resp.Header[k], ", "))
	}
	w.WriteString("\n")
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 5000))
	w.Write(bodyBytes)
	return w.String()
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysOfHeader(h http.Header) []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ToCurl renders the request as a copy-pasteable curl command.
// Header order is sorted for deterministic output.
func ToCurl(url, method string, headers map[string]string, body string) string {
	parts := []string{"curl -X " + method}
	for _, k := range sortedKeys(headers) {
		parts = append(parts, "-H '"+k+": "+headers[k]+"'")
	}
	if body != "" {
		parts = append(parts, "-d '"+body+"'")
	}
	parts = append(parts, "'"+url+"'")
	return strings.Join(parts, " \\\n  ")
}