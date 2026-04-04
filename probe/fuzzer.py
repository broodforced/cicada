## probe/fuzzer.py — directory and parameter fuzzing

import os
from core.toolchain import ToolChain
from shared.schema import Finding, Evidence


class Fuzzer:

	@staticmethod
	def run(targets, wordlist="", threads=25, timeout=300):
		if not ToolChain.available("ffuf"):
			return []
		if not wordlist or not os.path.isfile(wordlist):
			return []

		findings = []
		for target in targets[:20]:
			fuzz_url = target.rstrip("/") + "/FUZZ"
			hits = Fuzzer._fuzz_dirs(fuzz_url, wordlist, threads, timeout)
			findings.extend(hits)

		return findings

	@staticmethod
	def _fuzz_dirs(url, wordlist, threads, timeout):
		cmd = [
			"ffuf",
			"-u", url,
			"-w", wordlist,
			"-mc", "200,201,301,302,307,401,403,405,500",
			"-fc", "404",
			"-json",
			"-c",
			"-t", str(threads),
			"-timeout", "10",
			"-sf",
			"-se",
		]

		results = ToolChain.run(cmd, timeout=timeout, json_output=False)

		if isinstance(results, dict) and results.get("stdout"):
			return Fuzzer._parse_ffuf(results["stdout"], url)

		return []

	@staticmethod
	def _parse_ffuf(raw, base_url):
		import json as _json

		findings = []
		try:
			data = _json.loads(raw)
		except _json.JSONDecodeError:
			return Fuzzer._parse_ffuf_text(raw, base_url)

		results_list = data.get("results", [])
		for r in results_list:
			status = r.get("status", 0)
			fuzz_input = r.get("input", {}).get("FUZZ", "")
			result_url = r.get("url", f"{base_url.replace('FUZZ', fuzz_input)}")
			length = r.get("length", 0)

			if not fuzz_input:
				continue

			sev = Fuzzer._classify_finding(fuzz_input, status)
			if not sev:
				continue

			findings.append(Finding(
				title=f"Discovered: {fuzz_input} ({status})",
				severity=sev,
				category="information-disclosure",
				target=result_url,
				detail=f"ffuf found {result_url} — status {status}, length {length}",
				evidence=Evidence(request=f"GET {result_url}"),
				tool="ffuf",
				confidence="medium",
			))

		return findings

	@staticmethod
	def _parse_ffuf_text(raw, base_url):
		findings = []
		for line in raw.splitlines():
			line = line.strip()
			if not line or line.startswith("["):
				continue
			parts = line.split()
			if len(parts) >= 3:
				path = parts[0] if parts[0].startswith("/") else ""
				if path:
					findings.append(Finding(
						title=f"Discovered: {path}",
						severity="info",
						category="information-disclosure",
						target=f"{base_url.replace('/FUZZ', path)}",
						detail=f"ffuf found endpoint {path}",
						tool="ffuf",
						confidence="low",
					))
		return findings

	@staticmethod
	def _classify_finding(path, status):
		interesting = [
			"admin", "debug", "config", "env", "backup", "dump", "test",
			"staging", "internal", "graphql", "swagger", "api-docs",
			"phpinfo", "server-status", "actuator", "console", "trace",
			".git", ".env", ".svn", "wp-admin", "wp-config",
		]
		path_lower = path.lower()

		for keyword in interesting:
			if keyword in path_lower:
				if status in (200, 301, 302, 307):
					return "medium"
				if status == 403:
					return "low"

		if status == 500:
			return "low"

		if status in (200, 301, 302):
			return "info"

		return None
