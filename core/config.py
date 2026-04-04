## core/config.py — runtime config, tool detection, paths

import os
import sys
import json
import shutil
import platform
from pathlib import Path
from dataclasses import dataclass, field


TOOLS = {
	"nuclei": {"install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "required": True},
	"subfinder": {"install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "required": True},
	"httpx": {"install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", "required": True},
	"katana": {"install": "go install github.com/projectdiscovery/katana/cmd/katana@latest", "required": False},
	"ffuf": {"install": "go install github.com/ffuf/ffuf/v2@latest", "required": False},
}

WORDLIST_PATHS = [
	"~/SecLists/Discovery/Web-Content/common.txt",
	"/usr/share/wordlists/dirb/common.txt",
	"/usr/share/seclists/Discovery/Web-Content/common.txt",
	"/opt/SecLists/Discovery/Web-Content/common.txt",
]


@dataclass
class Config:
	target: str = ""
	mode: str = "normal"
	scope: list = field(default_factory=list)
	wordlist: str = ""
	threads: int = 25
	timeout: int = 30
	output_dir: str = ""
	report_path: str = ""
	h1_scope_file: str = ""
	nuclei_templates: str = ""
	nuclei_severity: str = ""
	tymbal_input: str = ""
	verbose: bool = False

	def __post_init__(self):
		if not self.output_dir:
			self.output_dir = os.getcwd()
		if not self.wordlist:
			self.wordlist = self._find_wordlist()

	def _find_wordlist(self):
		for p in WORDLIST_PATHS:
			expanded = os.path.expanduser(p)
			if os.path.isfile(expanded):
				return expanded
		return ""

	@staticmethod
	def detect_tools():
		status = {}
		go_bin = os.path.join(os.environ.get("GOPATH", os.path.expanduser("~/go")), "bin")
		paths = os.environ.get("PATH", "")
		if go_bin not in paths:
			os.environ["PATH"] = f"{go_bin}:{paths}"

		for name, info in TOOLS.items():
			found = shutil.which(name)
			status[name] = {
				"available": found is not None,
				"path": found or "",
				"required": info["required"],
				"install": info["install"],
			}
		return status

	@staticmethod
	def check_ready():
		status = Config.detect_tools()
		missing = [n for n, s in status.items() if s["required"] and not s["available"]]
		return missing, status

	@staticmethod
	def platform_info():
		return {
			"system": platform.system(),
			"machine": platform.machine(),
			"python": sys.version.split()[0],
		}

	@staticmethod
	def report_dir():
		system = platform.system()
		if system == "Darwin":
			desk = Path.home() / "Desktop"
			if desk.exists():
				return str(desk)
		return os.getcwd()
