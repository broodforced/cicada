## shared/schema.py — data contract between cicada and tymbal

import json
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone


@dataclass
class Evidence:
	request: str = ""
	response: str = ""
	screenshot: str = ""
	timestamp: str = ""

	def __post_init__(self):
		if not self.timestamp:
			self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
	title: str
	severity: str
	category: str
	target: str
	detail: str
	evidence: Evidence = field(default_factory=Evidence)
	tool: str = ""
	confidence: str = "medium"
	reference: str = ""
	finding_id: str = ""

	def __post_init__(self):
		if not self.finding_id:
			raw = f"{self.title}{self.target}{self.detail}"
			self.finding_id = hashlib.sha256(raw.encode()).hexdigest()[:12]


@dataclass
class Asset:
	host: str
	ip: str = ""
	ports: list = field(default_factory=list)
	technologies: list = field(default_factory=list)
	status_code: int = 0
	content_length: int = 0
	title: str = ""
	cdn: bool = False
	source: str = ""


@dataclass
class ReconData:
	target: str
	subdomains: list = field(default_factory=list)
	assets: list = field(default_factory=list)
	endpoints: list = field(default_factory=list)
	js_files: list = field(default_factory=list)
	parameters: list = field(default_factory=list)
	secrets: list = field(default_factory=list)
	timestamp: str = ""

	def __post_init__(self):
		if not self.timestamp:
			self.timestamp = datetime.now(timezone.utc).isoformat()

	def merge(self, other):
		for attr in ["subdomains", "endpoints", "js_files", "parameters"]:
			existing = set(getattr(self, attr))
			existing.update(getattr(other, attr))
			setattr(self, attr, list(existing))
		existing_secrets = {json.dumps(s, sort_keys=True) for s in self.secrets}
		for s in other.secrets:
			key = json.dumps(s, sort_keys=True)
			if key not in existing_secrets:
				self.secrets.append(s)
				existing_secrets.add(key)
		known_hosts = {a.host for a in self.assets}
		for asset in other.assets:
			if asset.host not in known_hosts:
				self.assets.append(asset)
				known_hosts.add(asset.host)


@dataclass
class ScanResult:
	target: str
	tool: str = "cicada"
	version: str = "0.1.0"
	recon: ReconData = None
	findings: list = field(default_factory=list)
	started: str = ""
	finished: str = ""
	mode: str = "normal"
	scope: list = field(default_factory=list)

	def __post_init__(self):
		if not self.started:
			self.started = datetime.now(timezone.utc).isoformat()
		if self.recon is None:
			self.recon = ReconData(target=self.target)

	def finish(self):
		self.finished = datetime.now(timezone.utc).isoformat()

	def add_finding(self, finding):
		known = {f.finding_id for f in self.findings}
		if finding.finding_id not in known:
			self.findings.append(finding)

	def to_json(self):
		return json.dumps(asdict(self), indent="\t", default=str)

	@classmethod
	def from_json(cls, raw):
		data = json.loads(raw) if isinstance(raw, str) else raw
		recon_data = data.pop("recon", {})
		findings_data = data.pop("findings", [])
		result = cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
		if recon_data:
			assets_raw = recon_data.pop("assets", [])
			result.recon = ReconData(**{k: v for k, v in recon_data.items() if k in ReconData.__dataclass_fields__})
			result.recon.assets = [Asset(**a) for a in assets_raw]
		for f in findings_data:
			ev = f.pop("evidence", {})
			finding = Finding(**{k: v for k, v in f.items() if k in Finding.__dataclass_fields__})
			finding.evidence = Evidence(**{k: v for k, v in ev.items() if k in Evidence.__dataclass_fields__})
			result.findings.append(finding)
		return result

	def summary(self):
		sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
		for f in self.findings:
			s = f.severity.lower()
			if s in sev:
				sev[s] += 1
		parts = [f"{v} {k}" for k, v in sev.items() if v > 0]
		hosts = len(self.recon.assets)
		subs = len(self.recon.subdomains)
		eps = len(self.recon.endpoints)
		return f"{subs} subdomains | {hosts} live hosts | {eps} endpoints | findings: {', '.join(parts) or 'none'}"
