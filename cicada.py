#!/usr/bin/env python3
## cicada.py — bug bounty hunting machine

import argparse
import sys
import os
import json

from core.config import Config
from core.pipeline import Pipeline
from decoder import codec
from decoder.log_analyzer import LogAnalyzer
from report.h1_template import H1Template
from shared.schema import ScanResult


VERSION = "0.1.0"

BANNER = r"""
           88                                88             
           ""                                88             
                                             88             
 ,adPPYba, 88  ,adPPYba, ,adPPYYba,  ,adPPYb,88 ,adPPYYba,  
a8"     "" 88 a8"     "" ""     `Y8 a8"    `Y88 ""     `Y8  
8b         88 8b         ,adPPPPP88 8b       88 ,adPPPPP88  
"8a,   ,aa 88 "8a,   ,aa 88,    ,88 "8a,   ,d88 88,    ,88  
 `"Ybbd8"' 88  `"Ybbd8"' `"8bbdP"Y8  `"8bbdP"Y8 `"8bbdP"Y8
                     ,
                `-.   \    .-'
        ,-"`````""-\__ |  /
         '-.._    _.-'` '-o,
             _>--:{{<   ) |)    )    )    )
         .-''      '-.__.-o`
        '-._____..-/`  |  \
                ,-'   /    `-.
                      `
"""

def banner(mode=""):
	print(BANNER)
	print(f"  cicada v{VERSION} | {mode}")
	print()


def cmd_scan(args):
	mode = "deep" if args.deep else "fast" if args.fast else "normal"
	banner(mode)

	missing, status = Config.check_ready()
	if missing:
		print(f"  [!] missing required tools: {', '.join(missing)}")
		print(f"  [!] install with:")
		for name in missing:
			print(f"      {status[name]['install']}")
		sys.exit(1)

	config = Config(
		target=args.target,
		mode=mode,
		wordlist=args.wordlist or "",
		threads=args.threads,
		output_dir=args.output or os.getcwd(),
		nuclei_templates=args.templates or "",
		nuclei_severity=args.severity or "",
		tymbal_input=args.tymbal or "",
		verbose=args.verbose,
	)

	if args.scope:
		config.scope = load_scope(args.scope)

	pipe = Pipeline(config)
	result = pipe.run()

	print(f"\n  {'─' * 40}")
	print(f"  {result['summary']}")
	print(f"  json  → {result['json']}")
	print(f"  html  → {result['html']}")

	if args.h1:
		generate_h1_reports(result["json"])


def cmd_decode(args):
	banner("decode")
	if args.b64e:
		print(codec.base64_encode(args.b64e))
	if args.b64d:
		print(codec.base64_decode(args.b64d))
	if args.urle:
		print(codec.url_encode(args.urle))
	if args.urld:
		print(codec.url_decode(args.urld))
	if args.hexe:
		print(codec.hex_encode(args.hexe))
	if args.hexd:
		print(codec.hex_decode(args.hexd))
	if args.jwt:
		print(codec.jwt_decode(args.jwt))
	if args.auto:
		results = codec.auto_decode(args.auto)
		if results:
			for method, decoded in results:
				print(f"  [{method}] {decoded}")
		else:
			print("  [*] no decodings found")


def cmd_analyze(args):
	banner("analyze")
	LogAnalyzer.analyze_and_print(args.logfile)


def cmd_report(args):
	banner("report")
	generate_h1_reports(args.json_file)


def cmd_ingest(args):
	banner("ingest")
	with open(args.tymbal_file, "r") as f:
		data = json.load(f)
	result = ScanResult.from_json(data)
	print(f"  target: {result.target}")
	print(f"  {result.summary()}")
	print(f"\n  tymbal data loaded — run scan with --tymbal {args.tymbal_file}")


def cmd_check(args):
	banner("check")
	missing, status = Config.check_ready()
	pinfo = Config.platform_info()
	print(f"  platform: {pinfo['system']} {pinfo['machine']}")
	print(f"  python:   {pinfo['python']}")
	print()
	for name, info in status.items():
		mark = "✓" if info["available"] else "✗"
		req = "required" if info["required"] else "optional"
		print(f"  [{mark}] {name:15} {req:10} {info['path'] or info['install']}")
	if missing:
		print(f"\n  [!] {len(missing)} required tools missing")
	else:
		print(f"\n  [✓] all required tools installed")


def generate_h1_reports(json_path):
	with open(json_path, "r") as f:
		result = ScanResult.from_json(json.load(f))

	reports = H1Template.generate_batch(result.findings)
	if not reports:
		print("  [*] no actionable findings for h1 reports")
		return

	out_dir = os.path.dirname(json_path)
	for i, r in enumerate(reports):
		path = os.path.join(out_dir, f"h1_report_{i+1}_{r['finding'].finding_id}.md")
		with open(path, "w") as f:
			f.write(r["report"])
		print(f"  h1 report → {path}")


def load_scope(scope_file):
	targets = []
	with open(scope_file, "r") as f:
		content = f.read().strip()

	try:
		data = json.loads(content)
		if isinstance(data, list):
			for item in data:
				if isinstance(item, dict):
					targets.append(item.get("asset_identifier", item.get("target", "")))
				elif isinstance(item, str):
					targets.append(item)
		elif isinstance(data, dict):
			for item in data.get("targets", data.get("scope", data.get("assets", []))):
				if isinstance(item, dict):
					targets.append(item.get("asset_identifier", item.get("target", "")))
				elif isinstance(item, str):
					targets.append(item)
	except json.JSONDecodeError:
		for line in content.splitlines():
			line = line.strip()
			if line and not line.startswith("#"):
				parts = line.split(",")
				targets.append(parts[0].strip())

	return [t for t in targets if t]


def interactive_mode():
	banner("interactive")
	target = input("  target: ").strip()
	if not target:
		print("  [!] target required")
		sys.exit(1)

	level = input("  mode (fast/normal/deep) [normal]: ").strip().lower() or "normal"
	if level not in ("fast", "normal", "deep"):
		level = "normal"

	config = Config(target=target, mode=level)
	missing, _ = Config.check_ready()
	if missing:
		print(f"  [!] missing tools: {', '.join(missing)}")
		sys.exit(1)

	pipe = Pipeline(config)
	result = pipe.run()
	print(f"\n  {'─' * 40}")
	print(f"  {result['summary']}")
	print(f"  json → {result['json']}")
	print(f"  html → {result['html']}")


def main():
	parser = argparse.ArgumentParser(
		prog="cicada",
		description="",
		usage=argparse.SUPPRESS,
		formatter_class=argparse.RawDescriptionHelpFormatter,
	)
	sub = parser.add_subparsers(dest="command")

	## scan
	p_scan = sub.add_parser("scan", help="run recon → probe → report pipeline")
	p_scan.add_argument("target", help="target domain or url")
	p_scan.add_argument("-f", "--fast", action="store_true", help="fast mode")
	p_scan.add_argument("-d", "--deep", action="store_true", help="deep mode")
	p_scan.add_argument("-w", "--wordlist", help="path to wordlist")
	p_scan.add_argument("-o", "--output", help="output directory")
	p_scan.add_argument("-t", "--threads", type=int, default=25, help="thread count")
	p_scan.add_argument("-s", "--scope", help="scope file (json/csv/txt)")
	p_scan.add_argument("--templates", help="nuclei template path")
	p_scan.add_argument("--severity", help="nuclei severity filter")
	p_scan.add_argument("--tymbal", help="ingest tymbal json before scanning")
	p_scan.add_argument("--h1", action="store_true", help="generate h1 report templates")
	p_scan.add_argument("-v", "--verbose", action="store_true")

	## decode
	p_dec = sub.add_parser("decode", help="encode/decode strings")
	p_dec.add_argument("--b64e", help="base64 encode")
	p_dec.add_argument("--b64d", help="base64 decode")
	p_dec.add_argument("--urle", help="url encode")
	p_dec.add_argument("--urld", help="url decode")
	p_dec.add_argument("--hexe", help="hex encode")
	p_dec.add_argument("--hexd", help="hex decode")
	p_dec.add_argument("--jwt", help="decode jwt token")
	p_dec.add_argument("--auto", help="try all decodings")

	## analyze
	p_log = sub.add_parser("analyze", help="decode encoded content from log")
	p_log.add_argument("logfile", help="path to log file")

	## report
	p_rpt = sub.add_parser("report", help="generate h1 reports from scan json")
	p_rpt.add_argument("json_file", help="cicada scan result json")

	## ingest
	p_ing = sub.add_parser("ingest", help="preview tymbal recon data")
	p_ing.add_argument("tymbal_file", help="tymbal output json")

	## check
	sub.add_parser("check", help="verify tool installation")

	args = parser.parse_args()

	if not args.command:
		if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
			args.target = sys.argv[1]
			args.fast = "-f" in sys.argv or "--fast" in sys.argv
			args.deep = "-d" in sys.argv or "--deep" in sys.argv
			args.wordlist = None
			args.threads = 25
			args.output = None
			args.scope = None
			args.templates = None
			args.severity = None
			args.tymbal = None
			args.h1 = False
			args.verbose = False
			cmd_scan(args)
		else:
			interactive_mode()
		return

	commands = {
		"scan": cmd_scan,
		"decode": cmd_decode,
		"analyze": cmd_analyze,
		"report": cmd_report,
		"ingest": cmd_ingest,
		"check": cmd_check,
	}
	commands[args.command](args)


if __name__ == "__main__":
	main()
