## report/evidence.py — request/response capture

import urllib.request
import ssl
from shared.schema import Evidence


class EvidenceCapture:

	@staticmethod
	def capture_request(url, method="GET", headers=None, body=None, timeout=10):
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE

		hdrs = headers or {"User-Agent": "Cicada/0.1.0"}
		req_str = f"{method} {url}\n"
		for k, v in hdrs.items():
			req_str += f"{k}: {v}\n"
		if body:
			req_str += f"\n{body}"

		resp_str = ""
		try:
			req = urllib.request.Request(url, headers=hdrs, method=method)
			if body:
				req.data = body.encode() if isinstance(body, str) else body
			resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
			resp_str = f"HTTP {resp.status} {resp.reason}\n"
			for k, v in resp.getheaders():
				resp_str += f"{k}: {v}\n"
			resp_str += f"\n{resp.read(5000).decode('utf-8', errors='replace')}"
		except urllib.error.HTTPError as e:
			resp_str = f"HTTP {e.code} {e.reason}\n"
			for k, v in e.headers.items():
				resp_str += f"{k}: {v}\n"
			try:
				resp_str += f"\n{e.read(5000).decode('utf-8', errors='replace')}"
			except Exception:
				pass
		except Exception as ex:
			resp_str = f"Error: {str(ex)}"

		return Evidence(
			request=req_str.strip(),
			response=resp_str.strip(),
		)

	@staticmethod
	def to_curl(url, method="GET", headers=None, body=None):
		parts = [f"curl -X {method}"]
		if headers:
			for k, v in headers.items():
				parts.append(f"-H '{k}: {v}'")
		if body:
			parts.append(f"-d '{body}'")
		parts.append(f"'{url}'")
		return " \\\n  ".join(parts)
