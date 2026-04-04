## probe/nuclei_scan.py — vulnerability scanning

from core.toolchain import ToolChain
from shared.schema import Finding, Evidence


class NucleiScan:

	@staticmethod
	def run(targets, severity="", templates="", timeout=600):
		if not ToolChain.available("nuclei"):
			return []

		stdin = "\n".join(targets)
		cmd = [
			"nuclei",
			"-silent",
			"-json",
			"-bulk-size", "25",
			"-rate-limit", "100",
			"-retries", "1",
		]

		if severity:
			cmd.extend(["-severity", severity])
		if templates:
			cmd.extend(["-t", templates])

		results = ToolChain.run(cmd, timeout=timeout, json_output=True, input_data=stdin)

		if not isinstance(results, list):
			return []

		findings = []
		for entry in results:
			info = entry.get("info", {})
			sev = info.get("severity", "info").lower()
			name = info.get("name", entry.get("template-id", "unknown"))
			matched = entry.get("matched-at", entry.get("host", ""))
			template_id = entry.get("template-id", "")
			desc = info.get("description", "")
			ref = info.get("reference", [])
			if isinstance(ref, list):
				ref = ", ".join(ref[:3])

			curl_cmd = entry.get("curl-command", "")
			req = entry.get("request", "")
			resp = entry.get("response", "")[:2000]

			finding = Finding(
				title=name,
				severity=sev,
				category=NucleiScan._categorize(template_id, name),
				target=matched,
				detail=desc or f"Nuclei template {template_id} matched",
				evidence=Evidence(
					request=curl_cmd or req,
					response=resp,
				),
				tool="nuclei",
				confidence="high" if sev in ("critical", "high") else "medium",
				reference=ref,
			)
			findings.append(finding)

		return findings

	@staticmethod
	def _categorize(template_id, name):
		tid = f"{template_id} {name}".lower()
		categories = {
			"xss": "xss",
			"sqli": "sql-injection",
			"sql": "sql-injection",
			"ssrf": "ssrf",
			"rce": "remote-code-execution",
			"lfi": "local-file-inclusion",
			"redirect": "open-redirect",
			"cors": "cors-misconfiguration",
			"cve": "known-vulnerability",
			"default-login": "default-credentials",
			"exposure": "information-disclosure",
			"token": "information-disclosure",
			"api": "api-vulnerability",
			"misconfig": "misconfiguration",
			"takeover": "subdomain-takeover",
		}
		for keyword, cat in categories.items():
			if keyword in tid:
				return cat
		return "other"
