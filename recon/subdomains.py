## recon/subdomains.py — subdomain enumeration

from urllib.parse import urlparse
from core.toolchain import ToolChain


class SubdomainEnum:

	@staticmethod
	def _extract_domain(target):
		if "://" in target:
			parsed = urlparse(target)
			return parsed.netloc.split(":")[0]
		return target.split("/")[0].split(":")[0]

	@staticmethod
	def run(target, timeout=120):
		domain = SubdomainEnum._extract_domain(target)

		if not ToolChain.available("subfinder"):
			return [domain]

		cmd = [
			"subfinder",
			"-d", domain,
			"-silent",
			"-all",
		]

		results = ToolChain.run(cmd, timeout=timeout)

		if isinstance(results, dict) and not results.get("success"):
			return [domain]

		if isinstance(results, dict):
			raw = results.get("stdout", "")
		else:
			raw = ""

		subs = set()
		for line in raw.splitlines():
			line = line.strip()
			if line and "." in line:
				subs.add(line.lower())

		if not subs:
			subs.add(domain)

		return sorted(subs)
