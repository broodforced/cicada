# Cicada

Recon → probe → check → nuclei → report, in one pass. Cicada is the deep-analysis half
of the broodforced toolchain: it enumerates a target's subdomains, probes the live hosts,
runs header/CORS checks, folds in nuclei findings, and emits a finding report
(JSON + HTML + markdown).

Not a bug-bounty submission tool — no platform formats, no PDF export. It's a
general-purpose offensive recon pipeline; the output is a plain, portable finding report.

## Pipeline

1. subdomain enumeration — subfinder-as-library (crtsh fast default)
2. http probing — native net/http: status, title, server, tech stack, CDN, IP
3. security checks — missing headers, CORS origin reflection
4. nuclei scan — tag subset (tech, misconfig, exposure)
5. report — JSON + HTML + markdown

## Build & run

    go build ./...
    go run ./cmd/cicada scan <target>

Targets must be your own or sanctioned test hosts (self-hosted DVWA / Juice Shop /
WebGoat, or public hosts meant for tool testing such as scanme.nmap.org and httpbin.org).
Never an unauthorized third party.