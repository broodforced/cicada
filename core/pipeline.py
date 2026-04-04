## core/pipeline.py — recon → probe → report orchestration

import sys
import json
import os
from datetime import datetime, timezone

from core.config import Config
from shared.schema import ScanResult, Finding, Evidence, ReconData
from recon.subdomains import SubdomainEnum
from recon.httpx_probe import HttpxProbe
from recon.endpoints import EndpointDiscovery
from recon.js_analysis import JsAnalyzer
from probe.nuclei_scan import NucleiScan
from probe.fuzzer import Fuzzer
from probe.checks import SecurityChecks
from report.generator import ReportGenerator
from report.h1_template import H1Template


class Pipeline:

	def __init__(self, config):
		self.config = config
		self.result = ScanResult(
			target=config.target,
			mode=config.mode,
			scope=config.scope,
		)

	def run(self):
		mode = self.config.mode
		self._print_phase("recon")

		if self.config.tymbal_input:
			self._ingest_tymbal()
		else:
			self._recon(mode)

		self._print_phase("probe")
		self._probe(mode)

		self._print_phase("report")
		self.result.finish()
		return self._report()

	def _recon(self, mode):
		target = self.config.target

		self._status("subdomain enumeration")
		subs = SubdomainEnum.run(target)
		self.result.recon.subdomains = subs

		self._status(f"probing {len(subs) or 1} hosts")
		hosts_to_probe = subs if subs else [target]
		assets = HttpxProbe.run(hosts_to_probe)
		self.result.recon.assets = assets

		if mode in ("normal", "deep"):
			self._status("endpoint discovery")
			live_urls = [f"https://{a.host}" for a in assets if a.status_code and not a.cdn]
			if not live_urls:
				live_urls = [target if target.startswith("http") else f"https://{target}"]
			endpoints, js_files = EndpointDiscovery.run(live_urls, deep=(mode == "deep"))
			self.result.recon.endpoints = endpoints
			self.result.recon.js_files = js_files

		if mode == "deep":
			self._status("javascript analysis")
			secrets, params = JsAnalyzer.run(self.result.recon.js_files)
			self.result.recon.secrets = secrets
			self.result.recon.parameters = params
			for secret in secrets:
				self.result.add_finding(Finding(
					title=f"Exposed Secret: {secret.get('type', 'unknown')}",
					severity="high",
					category="information-disclosure",
					target=secret.get("source", target),
					detail=f"Found {secret.get('type', 'secret')} in {secret.get('file', 'unknown')}: {secret.get('match', '')[:80]}",
					tool="js_analysis",
					confidence="medium",
				))

	def _probe(self, mode):
		target = self.config.target
		live_targets = []
		for a in self.result.recon.assets:
			if a.status_code and not a.cdn:
				proto = "https" if a.ports and 443 in a.ports else "https"
				live_targets.append(f"{proto}://{a.host}")
		if not live_targets:
			live_targets = [target if target.startswith("http") else f"https://{target}"]

		self._status("nuclei scan")
		severity = "critical,high,medium" if mode == "fast" else ""
		findings = NucleiScan.run(
			live_targets,
			severity=self.config.nuclei_severity or severity,
			templates=self.config.nuclei_templates,
		)
		for f in findings:
			self.result.add_finding(f)

		if mode in ("normal", "deep"):
			self._status("security checks")
			check_findings = SecurityChecks.run(live_targets)
			for f in check_findings:
				self.result.add_finding(f)

		if mode == "deep" and self.config.wordlist:
			self._status("fuzzing")
			fuzz_findings = Fuzzer.run(
				live_targets,
				wordlist=self.config.wordlist,
				threads=self.config.threads,
			)
			for f in fuzz_findings:
				self.result.add_finding(f)

	def _report(self):
		output_dir = self.config.output_dir
		base = self.config.target.replace("https://", "").replace("http://", "").replace("/", "_").split(":")[0]
		ts = datetime.now().strftime("%Y%m%d_%H%M%S")

		json_path = os.path.join(output_dir, f"cicada_{base}_{ts}.json")
		with open(json_path, "w") as f:
			f.write(self.result.to_json())

		html_path = os.path.join(output_dir, f"cicada_{base}_{ts}.html")
		ReportGenerator.generate(self.result, html_path)

		return {
			"json": json_path,
			"html": html_path,
			"summary": self.result.summary(),
		}

	def _ingest_tymbal(self):
		path = self.config.tymbal_input
		self._status(f"ingesting tymbal data from {path}")
		with open(path, "r") as f:
			data = json.load(f)
		tymbal_result = ScanResult.from_json(data)
		self.result.recon.merge(tymbal_result.recon)
		for finding in tymbal_result.findings:
			self.result.add_finding(finding)

	def _print_phase(self, name):
		phases = {"recon": "1", "probe": "2", "report": "3"}
		n = phases.get(name, "?")
		print(f"\n  [{n}/3] {name.upper()}")
		print(f"  {'─' * 40}")

	def _status(self, msg):
		print(f"    → {msg}")
