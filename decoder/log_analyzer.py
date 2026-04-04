## decoder/log_analyzer.py — scan logs for encoded content

import re
import os
from decoder import codec


ENCODED_PATTERN = re.compile(r"[A-Za-z0-9+/=]{10,}")
URL_ENCODED_PATTERN = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


class LogAnalyzer:

	@staticmethod
	def analyze(logfile_path):
		if not os.path.isfile(logfile_path):
			return []

		with open(logfile_path, "r", errors="ignore") as f:
			text = f.read()

		results = []
		seen = set()

		for match in JWT_PATTERN.finditer(text):
			token = match.group(0)
			if token in seen:
				continue
			seen.add(token)
			decoded = codec.jwt_decode(token)
			if "[!]" not in decoded:
				results.append({"encoded": token[:60] + "...", "method": "jwt", "decoded": decoded})

		for match in ENCODED_PATTERN.finditer(text):
			item = match.group(0)
			if item in seen:
				continue
			seen.add(item)
			for method, decoded in codec.auto_decode(item):
				if method == "jwt":
					continue
				results.append({"encoded": item, "method": method, "decoded": decoded})

		for match in URL_ENCODED_PATTERN.finditer(text):
			item = match.group(0)
			if item in seen:
				continue
			seen.add(item)
			decoded = codec.url_decode(item)
			if decoded != item:
				results.append({"encoded": item, "method": "url", "decoded": decoded})

		return results

	@staticmethod
	def analyze_and_print(logfile_path):
		results = LogAnalyzer.analyze(logfile_path)
		if not results:
			print("[*] No encoded values found.")
			return results

		for r in results:
			print(f"\n[+] Encoded: {r['encoded']}")
			print(f"    [{r['method']}] {r['decoded']}")

		return results
