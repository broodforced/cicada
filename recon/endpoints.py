## recon/endpoints.py — endpoint and url discovery

from core.toolchain import ToolChain


class EndpointDiscovery:

	@staticmethod
	def run(urls, deep=False, timeout=300):
		endpoints = set()
		js_files = set()

		katana_results = EndpointDiscovery._katana(urls, deep, timeout)
		for ep in katana_results:
			if ep.endswith(".js") or ".js?" in ep:
				js_files.add(ep)
			endpoints.add(ep)

		wayback_results = EndpointDiscovery._wayback(urls, timeout)
		for ep in wayback_results:
			if ep.endswith(".js") or ".js?" in ep:
				js_files.add(ep)
			endpoints.add(ep)

		return sorted(endpoints), sorted(js_files)

	@staticmethod
	def _katana(urls, deep, timeout):
		if not ToolChain.available("katana"):
			return []

		stdin = "\n".join(urls)
		cmd = [
			"katana",
			"-silent",
			"-jc",
			"-kf", "all",
			"-d", "3" if deep else "2",
			"-ct", "60",
			"-ef", "png,jpg,gif,svg,woff,woff2,ttf,eot,ico,css",
		]

		result = ToolChain.run(cmd, timeout=timeout, input_data=stdin)

		if isinstance(result, dict):
			raw = result.get("stdout", "")
			return [line.strip() for line in raw.splitlines() if line.strip()]

		return []

	@staticmethod
	def _wayback(urls, timeout):
		if not ToolChain.available("waybackurls"):
			return []

		collected = []
		for url in urls[:10]:
			domain = url.replace("https://", "").replace("http://", "").split("/")[0]
			cmd = ["waybackurls", domain]
			result = ToolChain.run(cmd, timeout=timeout)

			if isinstance(result, dict) and result.get("stdout"):
				for line in result["stdout"].splitlines():
					line = line.strip()
					if line and "=" in line:
						collected.append(line)

		return collected
