// Package recon holds cicada's reconnaissance layer. Subdomain enumeration is
// delegated to projectdiscovery/subfinder as an in-process library (no shelling
// out to a subfinder binary), matching the architecture decision.
package recon

import (
	"sort"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// SubdomainEnum enumerates subdomains for a domain using subfinder's passive
// sources. With no provider config on disk it uses the keyless sources (crt.sh,
// hackertarget, …); drop a provider-config.yaml in and pass it via config later
// to unlock the API-keyed sources.
func SubdomainEnum(domain string, sources ...string) ([]string, error) {
	opts := &runner.Options{
		Silent:             true,
		Timeout:            15,
		MaxEnumerationTime: 3, // minutes, hard bound
		DisableUpdateCheck: true,
	}
	if len(sources) > 0 {
		opts.Sources = goflags.StringSlice(sources)
	} else {
		opts.Sources = goflags.StringSlice{"crtsh"}
	}
	r, err := runner.NewRunner(opts)
	if err != nil {
		return nil, err
	}
	// host -> set of sources
	results, err := r.EnumerateSingleDomain(domain, nil)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(results))
	for host := range results {
		out = append(out, host)
	}
	sort.Strings(out)
	return out, nil
}