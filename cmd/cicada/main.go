// cicada — recon → probe → report bug-bounty pipeline. Go rewrite (in progress).
//
// This main.go is the scaffold: version, decode, analyze and check work against the
// ported schema + decoder. The scan/orchestration path is the next layer.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/broodforced/cicada/internal/decoder"
	"github.com/broodforced/cicada/internal/recon"
	"github.com/broodforced/cicada/internal/report"
	"github.com/broodforced/cicada/internal/schema"
)

const Version = "0.1.0"

func usage() {
	fmt.Printf(`  cicada v%s — bug bounty machine (Go)

  usage: cicada <command>

  commands:
    decode      encode/decode strings (--b64e/--b64d/--urle/--urld/--hexe/--hexd/--jwt/--auto)
    analyze     decode encoded content found in a log file
    report      render a scan JSON into a single-file HTML report
    ingest      preview a tymbal/cicada scan JSON (target + summary)
    check       verify tooling + show platform
    version     print the version

  examples:
    cicada decode --b64e hello
    cicada decode --auto aGVsbG8=
    cicada analyze scan.log
`, Version)
}

func cmdDecode(args []string) {
	fs := flag.NewFlagSet("decode", flag.ExitOnError)
	b64e := fs.String("b64e", "", "")
	b64d := fs.String("b64d", "", "")
	urle := fs.String("urle", "", "")
	urld := fs.String("urld", "", "")
	hexe := fs.String("hexe", "", "")
	hexd := fs.String("hexd", "", "")
	jwt := fs.String("jwt", "", "")
	auto := fs.String("auto", "", "")
	fs.Parse(args)

	if *b64e != "" {
		fmt.Println(decoder.Base64Encode(*b64e))
	}
	if *b64d != "" {
		fmt.Println(decoder.Base64Decode(*b64d))
	}
	if *urle != "" {
		fmt.Println(decoder.URLEncode(*urle))
	}
	if *urld != "" {
		fmt.Println(decoder.URLDecode(*urld))
	}
	if *hexe != "" {
		fmt.Println(decoder.HexEncode(*hexe))
	}
	if *hexd != "" {
		fmt.Println(decoder.HexDecode(*hexd))
	}
	if *jwt != "" {
		if j := decoder.JWTDecode(*jwt); j != nil {
			fmt.Printf("header:  %s\npayload: %s\n", j["header"], j["payload"])
		} else {
			fmt.Println("[!] not a decodable jwt")
		}
	}
	if *auto != "" {
		results := decoder.AutoDecode(*auto)
		if len(results) == 0 {
			fmt.Println("[*] no decodings found")
		}
		for _, r := range results {
			fmt.Printf("[%s] %s\n", r.Method, r.Decoded)
		}
	}
	if *b64e == "" && *b64d == "" && *urle == "" && *urld == "" &&
		*hexe == "" && *hexd == "" && *jwt == "" && *auto == "" {
		fs.Usage()
	}
}

func cmdAnalyze(args []string) {
	if len(args) < 1 {
		fmt.Println("usage: cicada analyze <logfile>")
		os.Exit(1)
	}
	decoder.AnalyzeAndPrint(args[0])
}

func cmdCheck() {
	fmt.Printf("  cicada v%s\n", Version)
	fmt.Printf("  platform: %s %s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println("  [*] scan orchestration (subfinder/httpx/nuclei/…) not wired yet")
}

func cmdReport(args []string) {
	if len(args) < 1 {
		fmt.Println("usage: cicada report <scan.json>")
		os.Exit(1)
	}
	r, err := schema.LoadJSON(args[0])
	if err != nil {
		fmt.Println("[!] cannot load:", err)
		os.Exit(1)
	}
	out := strings.TrimSuffix(args[0], ".json") + ".html"
	if err := report.Generate(r, out); err != nil {
		fmt.Println("[!]", err)
		os.Exit(1)
	}
	fmt.Printf("  report → %s\n", out)
}

func cmdIngest(args []string) {
	if len(args) < 1 {
		fmt.Println("usage: cicada ingest <tymbal.json>")
		os.Exit(1)
	}
	r, err := schema.LoadJSON(args[0])
	if err != nil {
		fmt.Println("[!] cannot load:", err)
		os.Exit(1)
	}
	fmt.Printf("  target: %s\n", r.Target)
	fmt.Printf("  %s\n", r.Summary())
	fmt.Printf("\n  run scan with --tymbal %s\n", args[0])
}

func cmdScan(args []string) {
	if len(args) < 1 {
		fmt.Println("usage: cicada scan <domain>")
		os.Exit(1)
	}
	domain := args[0]
	r := schema.NewScanResult(domain, "normal")

	fmt.Println("  [1] subdomain enumeration")
	subs, err := recon.SubdomainEnum(domain)
	if err != nil {
		fmt.Println("[!] subdomain enum:", err)
		os.Exit(1)
	}
	for _, s := range subs {
		r.AddSubdomain(s)
	}
	r.AddSubdomain(domain)

	fmt.Println("  [2] http probing")
	for _, s := range r.Recon.Subdomains {
		if a, ok := recon.ProbeHost(s); ok {
			r.AddAsset(a)
		}
	}

	fmt.Println("  [3] security checks")
	for _, a := range r.Recon.Assets {
		recon.HeaderChecks(a.Host, &r)
		recon.CORS(a.Host, &r)
	}

	fmt.Println("  [4] nuclei scan")
	recon.NucleiScanInto(domain, &r)

	r.Finish()

	// outputs: JSON + HTML report + H1 templates
	jsonOut := domain + ".cicada.json"
	if err := r.WriteJSON(jsonOut); err != nil {
		fmt.Println("[!] write:", err)
		os.Exit(1)
	}
	htmlOut := domain + ".cicada.html"
	if err := report.Generate(r, htmlOut); err != nil {
		fmt.Println("[!] report:", err)
		os.Exit(1)
	}
	for i, hr := range report.GenerateBatch(r.Findings) {
		p := fmt.Sprintf("h1_report_%d_%s.md", i+1, hr.Finding.FindingID)
		if err := os.WriteFile(p, []byte(hr.Report), 0o644); err == nil {
			fmt.Printf("  h1 → %s\n", p)
		}
	}

	fmt.Printf("  %s\n", r.Summary())
	fmt.Printf("  json → %s\n", jsonOut)
	fmt.Printf("  html → %s\n", htmlOut)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "decode":
		cmdDecode(os.Args[2:])
	case "analyze":
		cmdAnalyze(os.Args[2:])
	case "report":
		cmdReport(os.Args[2:])
	case "ingest":
		cmdIngest(os.Args[2:])
	case "scan":
		cmdScan(os.Args[2:])
	case "check":
		cmdCheck()
	case "version", "-V", "--version":
		fmt.Printf("cicada v%s\n", Version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
	}
}
