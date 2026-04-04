## probe/checks.py — custom security checks

import urllib.request
import ssl
import json
from shared.schema import Finding, Evidence


class SecurityChecks:

	@staticmethod
	def run(targets):
		findings = []
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE

		for target in targets[:30]:
			findings.extend(SecurityChecks._cors_check(target, ctx))
			findings.extend(SecurityChecks._header_check(target, ctx))
			findings.extend(SecurityChecks._redirect_check(target, ctx))

		return findings

	@staticmethod
	def _fetch(url, ctx, headers=None, redirect=True):
		try:
			req = urllib.request.Request(url, headers=headers or {"User-Agent": "Cicada/0.1.0"})
			if redirect:
				resp = urllib.request.urlopen(req, timeout=10, context=ctx)
			else:
				import http.client
				from urllib.parse import urlparse
				parsed = urlparse(url)
				conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
				conn = conn_cls(parsed.netloc, timeout=10, context=ctx if parsed.scheme == "https" else None)
				path = parsed.path or "/"
				if parsed.query:
					path += f"?{parsed.query}"
				hdrs = headers or {"User-Agent": "Cicada/0.1.0"}
				conn.request("GET", path, headers=hdrs)
				resp = conn.getresponse()
				resp.url = url
				resp.getheaders_dict = dict(resp.getheaders())
				return resp
			return resp
		except Exception:
			return None

	@staticmethod
	def _cors_check(target, ctx):
		findings = []
		evil_origins = [
			"https://evil.com",
			"null",
		]

		for origin in evil_origins:
			try:
				req = urllib.request.Request(target, headers={
					"User-Agent": "Cicada/0.1.0",
					"Origin": origin,
				})
				resp = urllib.request.urlopen(req, timeout=10, context=ctx)
				acao = resp.getheader("Access-Control-Allow-Origin")
				acac = resp.getheader("Access-Control-Allow-Credentials")

				if not acao:
					continue

				if acao == "*" and acac and acac.lower() == "true":
					findings.append(Finding(
						title="CORS: Wildcard with credentials",
						severity="high",
						category="cors-misconfiguration",
						target=target,
						detail=f"ACAO: {acao}, ACAC: {acac} — allows any origin with credentials",
						evidence=Evidence(
							request=f"Origin: {origin}",
							response=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
						),
						tool="checks",
						confidence="high",
					))
				elif acao == origin and origin == "https://evil.com":
					sev = "high" if acac and acac.lower() == "true" else "medium"
					findings.append(Finding(
						title="CORS: Origin reflection",
						severity=sev,
						category="cors-misconfiguration",
						target=target,
						detail=f"Server reflects arbitrary origin {origin} — ACAO: {acao}, ACAC: {acac}",
						evidence=Evidence(
							request=f"Origin: {origin}",
							response=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
						),
						tool="checks",
						confidence="high",
					))
				elif acao == "null":
					findings.append(Finding(
						title="CORS: Null origin accepted",
						severity="medium",
						category="cors-misconfiguration",
						target=target,
						detail=f"Server accepts null origin — exploitable via sandboxed iframe",
						evidence=Evidence(
							request=f"Origin: null",
							response=f"Access-Control-Allow-Origin: {acao}",
						),
						tool="checks",
						confidence="high",
					))
			except Exception:
				continue

		return findings

	@staticmethod
	def _header_check(target, ctx):
		findings = []
		try:
			req = urllib.request.Request(target, headers={"User-Agent": "Cicada/0.1.0"})
			resp = urllib.request.urlopen(req, timeout=10, context=ctx)
			headers = {k.lower(): v for k, v in resp.getheaders()}

			checks = {
				"strict-transport-security": ("Missing HSTS header", "low", "misconfiguration"),
				"x-frame-options": ("Missing X-Frame-Options", "low", "misconfiguration"),
				"content-security-policy": ("Missing Content-Security-Policy", "info", "misconfiguration"),
			}

			for header, (title, sev, cat) in checks.items():
				if header not in headers:
					findings.append(Finding(
						title=title,
						severity=sev,
						category=cat,
						target=target,
						detail=f"Response is missing the {header} header",
						tool="checks",
						confidence="high",
					))

			server = headers.get("server", "")
			powered = headers.get("x-powered-by", "")
			if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/"]):
				findings.append(Finding(
					title=f"Server version disclosure: {server}",
					severity="info",
					category="information-disclosure",
					target=target,
					detail=f"Server header reveals: {server}",
					tool="checks",
					confidence="high",
				))
			if powered:
				findings.append(Finding(
					title=f"Technology disclosure: {powered}",
					severity="info",
					category="information-disclosure",
					target=target,
					detail=f"X-Powered-By header reveals: {powered}",
					tool="checks",
					confidence="high",
				))
		except Exception:
			pass

		return findings

	@staticmethod
	def _redirect_check(target, ctx):
		findings = []
		payloads = [
			("//{target}@evil.com", "authority-based"),
			("//evil.com/%2f..", "path-based"),
			("/\\evil.com", "backslash-based"),
		]

		base = target.rstrip("/")
		for payload_tpl, technique in payloads:
			payload = payload_tpl.replace("{target}", base.split("//")[-1].split("/")[0])
			test_url = f"{base}{payload}"
			try:
				req = urllib.request.Request(test_url, headers={"User-Agent": "Cicada/0.1.0"})
				resp = urllib.request.urlopen(req, timeout=10, context=ctx)
				final = resp.url
				if "evil.com" in final:
					findings.append(Finding(
						title=f"Open redirect ({technique})",
						severity="medium",
						category="open-redirect",
						target=test_url,
						detail=f"Redirect to {final} via {technique} payload",
						evidence=Evidence(
							request=f"GET {test_url}",
							response=f"Redirected to: {final}",
						),
						tool="checks",
						confidence="high",
					))
			except Exception:
				continue

		return findings
