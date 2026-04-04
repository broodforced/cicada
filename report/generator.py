## report/generator.py — single-file html report

import html


class ReportGenerator:

	@staticmethod
	def generate(result, output_path):
		findings = sorted(result.findings, key=lambda f: ReportGenerator._sev_rank(f.severity))
		recon = result.recon

		sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
		for f in findings:
			s = f.severity.lower()
			if s in sev_counts:
				sev_counts[s] += 1

		body = ReportGenerator._render(result, findings, recon, sev_counts)
		with open(output_path, "w") as f:
			f.write(body)

	@staticmethod
	def _sev_rank(sev):
		return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev.lower(), 5)

	@staticmethod
	def _sev_color(sev):
		return {
			"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706",
			"low": "#2563eb", "info": "#6b7280",
		}.get(sev.lower(), "#6b7280")

	@staticmethod
	def _esc(text):
		return html.escape(str(text)) if text else ""

	@staticmethod
	def _render(result, findings, recon, sev_counts):
		e = ReportGenerator._esc
		sc = ReportGenerator._sev_color

		finding_html = ""
		for f in findings:
			color = sc(f.severity)
			ev_block = ""
			if f.evidence.request or f.evidence.response:
				parts = []
				if f.evidence.request:
					parts.append(f'<div class="ev-section"><span class="ev-label">request</span><pre>{e(f.evidence.request)}</pre></div>')
				if f.evidence.response:
					parts.append(f'<div class="ev-section"><span class="ev-label">response</span><pre>{e(f.evidence.response[:1500])}</pre></div>')
				ev_block = f'<details class="ev"><summary>evidence</summary>{"".join(parts)}</details>'

			ref_block = f'<div class="finding-ref">ref: {e(f.reference)}</div>' if f.reference else ""
			finding_html += f'''<div class="finding">
<div class="fh"><span class="sev" style="background:{color}">{e(f.severity.upper())}</span><span class="ft">{e(f.title)}</span><span class="ftool">{e(f.tool)}</span></div>
<div class="ftarget">{e(f.target)}</div>
<div class="fdetail">{e(f.detail)}</div>
{ref_block}{ev_block}</div>
'''

		asset_html = ""
		for a in recon.assets[:200]:
			tech = ", ".join(a.technologies[:5]) if a.technologies else ""
			cdn = "CDN" if a.cdn else ""
			asset_html += f"<tr><td>{e(a.host)}</td><td>{a.status_code or ''}</td><td>{e(a.title)}</td><td>{e(tech)}</td><td>{cdn}</td></tr>\n"

		ep_html = ""
		if recon.endpoints:
			ep_html = "".join(f'<div class="ep">{e(ep)}</div>' for ep in recon.endpoints[:500])

		secret_html = ""
		if recon.secrets:
			for s in recon.secrets:
				secret_html += f'<div class="finding"><span class="sev" style="background:#ea580c">SECRET</span> <b>{e(s.get("type",""))}</b> in {e(s.get("file","")[:80])}<br><code class="fdetail">{e(s.get("match","")[:100])}</code></div>\n'

		return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>cicada — {e(result.target)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{--bg:#0a0a0a;--sf:#141414;--bd:#222;--tx:#e0e0e0;--mt:#888;--ac:#22d3ee}}
body{{background:var(--bg);color:var(--tx);font:14px/1.6 'SF Mono',Monaco,Consolas,monospace;padding:2rem;max-width:1200px;margin:0 auto}}
h1{{font-size:1.4rem;color:var(--ac);margin-bottom:.25rem}}
h2{{font-size:1.1rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--bd)}}
.meta{{color:var(--mt);font-size:.85rem;margin-bottom:2rem}}
.stats{{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0 2rem}}
.stat{{background:var(--sf);border:1px solid var(--bd);border-radius:6px;padding:.75rem 1.25rem;text-align:center;min-width:100px}}
.sv{{font-size:1.5rem;font-weight:700}}.sl{{font-size:.75rem;color:var(--mt);text-transform:uppercase;letter-spacing:.05em}}
.finding{{background:var(--sf);border:1px solid var(--bd);border-radius:6px;padding:1rem;margin-bottom:.75rem}}
.fh{{display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem;flex-wrap:wrap}}
.sev{{color:#fff;font-size:.7rem;font-weight:700;padding:.2rem .5rem;border-radius:3px;letter-spacing:.03em}}
.ft{{font-weight:600;flex:1}}.ftool{{color:var(--mt);font-size:.8rem}}
.ftarget{{color:var(--ac);font-size:.85rem;margin-bottom:.25rem;word-break:break-all}}
.fdetail{{color:var(--mt);font-size:.85rem}}.finding-ref{{color:var(--mt);font-size:.8rem;margin-top:.25rem}}
.ev{{margin-top:.5rem}}.ev summary{{color:var(--ac);font-size:.8rem;cursor:pointer}}
.ev-section{{margin:.5rem 0}}.ev-label{{font-size:.75rem;color:var(--mt);text-transform:uppercase}}
.ev pre{{background:#0d0d0d;border:1px solid var(--bd);border-radius:4px;padding:.5rem;overflow-x:auto;font-size:.8rem;max-height:300px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th,td{{text-align:left;padding:.5rem .75rem;border-bottom:1px solid var(--bd)}}
th{{color:var(--mt);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}}
tr:hover td{{background:var(--sf)}}
.ep{{font-size:.8rem;color:var(--mt);padding:.15rem 0;word-break:break-all}}
.empty{{color:var(--mt);font-style:italic;padding:1rem}}
</style>
</head>
<body>
<h1>cicada</h1>
<div class="meta">{e(result.target)} &middot; {result.mode} mode &middot; {result.started[:19] if result.started else ""} &mdash; {result.finished[:19] if result.finished else ""}</div>

<div class="stats">
<div class="stat"><div class="sv">{len(recon.subdomains)}</div><div class="sl">subdomains</div></div>
<div class="stat"><div class="sv">{len(recon.assets)}</div><div class="sl">live hosts</div></div>
<div class="stat"><div class="sv">{len(recon.endpoints)}</div><div class="sl">endpoints</div></div>
<div class="stat"><div class="sv" style="color:#dc2626">{sev_counts["critical"]}</div><div class="sl">critical</div></div>
<div class="stat"><div class="sv" style="color:#ea580c">{sev_counts["high"]}</div><div class="sl">high</div></div>
<div class="stat"><div class="sv" style="color:#d97706">{sev_counts["medium"]}</div><div class="sl">medium</div></div>
<div class="stat"><div class="sv" style="color:#2563eb">{sev_counts["low"]}</div><div class="sl">low</div></div>
<div class="stat"><div class="sv" style="color:#6b7280">{sev_counts["info"]}</div><div class="sl">info</div></div>
</div>

<h2>findings ({len(findings)})</h2>
{finding_html or '<div class="empty">no findings</div>'}

<h2>live assets ({len(recon.assets)})</h2>
<table><thead><tr><th>host</th><th>status</th><th>title</th><th>tech</th><th>cdn</th></tr></thead>
<tbody>{asset_html or '<tr><td colspan="5" class="empty">no assets discovered</td></tr>'}</tbody></table>

<h2>endpoints ({len(recon.endpoints)})</h2>
{ep_html or '<div class="empty">no endpoints discovered</div>'}

{f'<h2>secrets ({len(recon.secrets)})</h2>{secret_html}' if recon.secrets else ""}

</body></html>'''
