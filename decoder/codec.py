## decoder/codec.py — encoding and decoding operations

import base64
import urllib.parse
import binascii
import html as html_lib
import string


def is_printable(s, threshold=0.85):
	printables = sum(1 for c in s if c in string.printable)
	return (printables / max(len(s), 1)) >= threshold


def base64_encode(data):
	return base64.b64encode(data.encode()).decode()


def base64_decode(data):
	try:
		padding = 4 - len(data) % 4
		if padding != 4:
			data += "=" * padding
		return base64.b64decode(data.encode()).decode("utf-8", errors="replace")
	except Exception:
		return None


def url_encode(data):
	return urllib.parse.quote(data)


def url_decode(data):
	try:
		return urllib.parse.unquote(data)
	except Exception:
		return None


def hex_encode(data):
	return data.encode().hex()


def hex_decode(data):
	try:
		return bytes.fromhex(data).decode("utf-8", errors="replace")
	except Exception:
		return None


def html_encode(data):
	return html_lib.escape(data)


def html_decode(data):
	try:
		return html_lib.unescape(data)
	except Exception:
		return None


def jwt_decode(token):
	parts = token.split(".")
	if len(parts) < 2:
		return None
	try:
		header = base64_decode(parts[0].replace("-", "+").replace("_", "/"))
		payload = base64_decode(parts[1].replace("-", "+").replace("_", "/"))
		if header and payload:
			return {"header": header, "payload": payload}
		return None
	except Exception:
		return None


def auto_decode(data):
	results = []

	b64 = base64_decode(data)
	if b64 and b64 != data and is_printable(b64):
		results.append(("base64", b64))

	hx = hex_decode(data)
	if hx and hx != data and is_printable(hx):
		results.append(("hex", hx))

	urld = url_decode(data)
	if urld and urld != data and is_printable(urld):
		results.append(("url", urld))

	htmld = html_decode(data)
	if htmld and htmld != data and is_printable(htmld):
		results.append(("html", htmld))

	if data.count(".") == 2 and data.startswith("eyJ"):
		jwt = jwt_decode(data)
		if jwt:
			results.append(("jwt", f"header: {jwt['header']}\npayload: {jwt['payload']}"))

	return results
