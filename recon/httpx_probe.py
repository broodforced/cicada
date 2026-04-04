## recon/httpx_probe.py — live host probing

from core.toolchain import ToolChain
from shared.schema import Asset


class HttpxProbe:

	@staticmethod
	def run(hosts, timeout=120):
		if not ToolChain.available("httpx"):
			return HttpxProbe._fallback(hosts)

		stdin = "\n".join(hosts)
		cmd = [
			"httpx",
			"-silent",
			"-json",
			"-title",
			"-status-code",
			"-content-length",
			"-tech-detect",
			"-cdn",
			"-follow-redirects",
			"-threads", "30",
		]

		results = ToolChain.run(cmd, timeout=timeout, json_output=True, input_data=stdin)

		if not isinstance(results, list):
			return HttpxProbe._fallback(hosts)

		assets = []
		seen = set()
		for entry in results:
			host = entry.get("input", entry.get("host", ""))
			if not host or host in seen:
				continue
			seen.add(host)

			tech = entry.get("tech", [])
			if isinstance(tech, str):
				tech = [tech]

			asset = Asset(
				host=host,
				ip=entry.get("a", [""])[0] if isinstance(entry.get("a"), list) else entry.get("a", ""),
				status_code=entry.get("status_code", entry.get("status-code", 0)),
				content_length=entry.get("content_length", entry.get("content-length", 0)),
				title=entry.get("title", ""),
				technologies=tech,
				cdn=entry.get("cdn", False),
				source="httpx",
			)
			assets.append(asset)

		if not assets:
			return HttpxProbe._fallback(hosts)

		return assets

	@staticmethod
	def _fallback(hosts):
		return [Asset(host=h, source="fallback") for h in hosts[:50]]
