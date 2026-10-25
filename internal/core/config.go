// Package core holds cicada's runtime config and tool detection.
// Go port of core/config.py.
package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type toolInfo struct {
	Install  string
	Required bool
}

// TOOLS is the external toolchain cicada orchestrates.
var TOOLS = map[string]toolInfo{
	"nuclei":    {"go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", true},
	"subfinder": {"go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", true},
	"httpx":     {"go install github.com/projectdiscovery/httpx/cmd/httpx@latest", true},
	"katana":    {"go install github.com/projectdiscovery/katana/cmd/katana@latest", false},
	"ffuf":      {"go install github.com/ffuf/ffuf/v2@latest", false},
}

var wordlistPaths = []string{
	"~/SecLists/Discovery/Web-Content/common.txt",
	"/usr/share/wordlists/dirb/common.txt",
	"/usr/share/seclists/Discovery/Web-Content/common.txt",
	"/opt/SecLists/Discovery/Web-Content/common.txt",
}

// Config is the runtime configuration for a scan.
type Config struct {
	Target          string
	Mode            string
	Scope           []string
	Wordlist        string
	Threads         int
	Timeout         int
	OutputDir       string
	ReportPath      string
	H1ScopeFile     string
	NucleiTemplates string
	NucleiSeverity  string
	TymbalInput     string
	Verbose         bool
}

// PostInit fills defaults the Python __post_init__ sets.
func (c *Config) PostInit() {
	if c.OutputDir == "" {
		c.OutputDir, _ = os.Getwd()
	}
	if c.Wordlist == "" {
		c.Wordlist = findWordlist()
	}
}

func findWordlist() string {
	for _, p := range wordlistPaths {
		if p[0] == '~' {
			home, err := os.UserHomeDir()
			if err != nil {
				continue
			}
			p = filepath.Join(home, p[1:])
		}
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// ToolStatus reports whether a tool is installed and how to install it.
type ToolStatus struct {
	Available bool
	Path      string
	Required  bool
	Install   string
}

// DetectTools checks which of TOOLS are on the PATH.
func DetectTools() map[string]ToolStatus {
	goBin := filepath.Join(firstNonEmpty(os.Getenv("GOPATH"), homeGoPath()), "bin")
	os.Setenv("PATH", goBin+":"+os.Getenv("PATH"))

	status := map[string]ToolStatus{}
	for name, info := range TOOLS {
		found, err := exec.LookPath(name)
		status[name] = ToolStatus{
			Available: err == nil,
			Path:      found,
			Required:  info.Required,
			Install:   info.Install,
		}
	}
	return status
}

func homeGoPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "go")
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// CheckReady returns the missing required tools and the full status map.
func CheckReady() ([]string, map[string]ToolStatus) {
	status := DetectTools()
	var missing []string
	for name, s := range status {
		if s.Required && !s.Available {
			missing = append(missing, name)
		}
	}
	return missing, status
}

// PlatformInfo reports OS/arch/Go, replacing the Python "python" field.
func PlatformInfo() map[string]string {
	sys := map[string]string{"darwin": "Darwin", "linux": "Linux", "windows": "Windows"}[runtime.GOOS]
	if sys == "" {
		sys = runtime.GOOS
	}
	return map[string]string{
		"system":  sys,
		"machine": runtime.GOARCH,
		"go":      runtime.Version(),
	}
}

// ReportDir picks the Desktop on macOS, cwd elsewhere (Python report_dir behavior).
func ReportDir() string {
	if runtime.GOOS == "darwin" {
		if home, err := os.UserHomeDir(); err == nil {
			desk := filepath.Join(home, "Desktop")
			if fi, err := os.Stat(desk); err == nil && fi.IsDir() {
				return desk
			}
		}
	}
	cwd, _ := os.Getwd()
	return cwd
}

var _ = strings.TrimSpace // keep strings imported for future scope parsing