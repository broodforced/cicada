## recon/js_analysis.py — extract secrets and params from javascript

import re
import urllib.request
import ssl


SECRET_PATTERNS = {
	"aws_key": r"(?:AKIA|ASIA)[A-Z0-9]{16}",
	"aws_secret": r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)['\"\s=:]+([A-Za-z0-9/+=]{40})",
	"google_api": r"AIza[0-9A-Za-z\-_]{35}",
	"github_token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
	"slack_token": r"xox[baprs]-[0-9a-zA-Z\-]{10,250}",
	"jwt": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
	"private_key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
	"generic_secret": r"(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key)['\"\s=:]+['\"]([A-Za-z0-9/+=_\-]{16,})['\"]",
	"bearer": r"[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*",
	"firebase": r"[a-z0-9-]+\.firebaseio\.com",
	"s3_bucket": r"[a-z0-9.-]+\.s3\.amazonaws\.com",
	"internal_ip": r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
}

PARAM_PATTERN = re.compile(
	r'(?:'
	r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})='
	r'|'
	r'(?:params?|query|data)\s*[\[.]\s*[\'"]([a-zA-Z_][a-zA-Z0-9_]{1,30})[\'"]'
	r'|'
	r'(?:get|post|put|delete|fetch)\s*\([^)]*[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})='
	r')'
)

ENDPOINT_PATTERN = re.compile(
	r'["\'](/(?:api|v[0-9]|graphql|rest|auth|admin|internal|debug|config|health|status|swagger|docs)[a-zA-Z0-9/_\-.]*)["\']'
)


class JsAnalyzer:

	@staticmethod
	def run(js_urls, timeout=15):
		secrets = []
		params = set()

		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE

		for url in js_urls[:100]:
			try:
				req = urllib.request.Request(url, headers={"User-Agent": "Cicada/0.1.0"})
				resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
				content = resp.read().decode("utf-8", errors="ignore")
			except Exception:
				continue

			for secret_type, pattern in SECRET_PATTERNS.items():
				for match in re.finditer(pattern, content):
					secrets.append({
						"type": secret_type,
						"match": match.group(0)[:120],
						"file": url,
						"source": url.split("/")[-1].split("?")[0],
					})

			for match in PARAM_PATTERN.finditer(content):
				param = match.group(1) or match.group(2) or match.group(3)
				if param:
					params.add(param)

			for match in ENDPOINT_PATTERN.finditer(content):
				params.add(match.group(1))

		return secrets, sorted(params)
