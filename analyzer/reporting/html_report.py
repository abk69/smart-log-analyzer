"""Standalone HTML security report writer."""

from __future__ import annotations

import html
import json
from pathlib import Path

from analyzer.exceptions import ReportGenerationError
from analyzer.models import AnalysisResult
from analyzer.reporting.serialize import build_report_document


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _severity_class(severity: str) -> str:
    return f"sev-{(severity or 'unknown').lower()}"


def _bar_width(count: int, maximum: int) -> int:
    if maximum <= 0:
        return 0
    return max(4, int((count / maximum) * 100)) if count else 0


def _render_html(document: dict) -> str:
    meta = document["metadata"]
    analysis = document["analysis"]
    stats = document["statistics"]
    summary = document["summary"]
    alerts = document["alerts"]
    incidents = document["incidents"]

    alert_sev = summary["alert_severity"]
    attack_types = summary["attack_types"]
    max_sev = max(alert_sev.values()) if alert_sev else 0
    max_attack = max(attack_types.values()) if attack_types else 0

    top_ip = stats.get("top_ip", ("-", 0))
    top_user = stats.get("top_user", ("-", 0))
    # statistics stores tuples; after json_safe they become lists
    if isinstance(top_ip, (list, tuple)) and len(top_ip) == 2:
        top_ip_label, top_ip_count = top_ip[0], top_ip[1]
    else:
        top_ip_label, top_ip_count = "-", 0
    if isinstance(top_user, (list, tuple)) and len(top_user) == 2:
        top_user_label, top_user_count = top_user[0], top_user[1]
    else:
        top_user_label, top_user_count = "-", 0

    timeline_rows = []
    for alert in sorted(alerts, key=lambda a: a.get("timestamp") or ""):
        timeline_rows.append(
            "<tr>"
            f"<td>{_esc(alert.get('timestamp'))}</td>"
            f"<td><span class='badge {_severity_class(alert.get('severity', ''))}'>"
            f"{_esc(alert.get('alert_type'))}</span></td>"
            f"<td>{_esc(alert.get('severity'))}</td>"
            f"<td>{_esc(alert.get('ip_address'))}</td>"
            f"<td>{_esc(alert.get('username'))}</td>"
            "</tr>"
        )

    alert_rows = []
    for alert in alerts:
        evidence_json = json.dumps(alert.get("evidence", {}), indent=2, ensure_ascii=False)
        alert_rows.append(
            "<tr>"
            f"<td><span class='badge {_severity_class(alert.get('severity', ''))}'>"
            f"{_esc(alert.get('severity'))}</span></td>"
            f"<td>{_esc(alert.get('alert_type'))}</td>"
            f"<td>{_esc(alert.get('timestamp'))}</td>"
            f"<td>{_esc(alert.get('username'))}</td>"
            f"<td>{_esc(alert.get('ip_address'))}</td>"
            f"<td>{_esc(alert.get('confidence'))}</td>"
            f"<td>{_esc(alert.get('risk_score'))}</td>"
            f"<td class='desc'>{_esc(alert.get('description'))}"
            "<details><summary>View Evidence</summary>"
            f"<pre>{_esc(evidence_json)}</pre></details></td>"
            "</tr>"
        )

    incident_cards = []
    for index, incident in enumerate(incidents, start=1):
        chain = (
            incident.get("metadata", {}).get("attack_chain")
            or incident.get("evidence", {}).get("observed_alert_chain")
            or []
        )
        chain_html = " → ".join(_esc(step) for step in chain) if chain else "N/A"
        evidence_json = json.dumps(incident.get("evidence", {}), indent=2, ensure_ascii=False)
        incident_cards.append(
            f"""
            <article class="incident-card">
              <header>
                <h3>INCIDENT-{index:03d}</h3>
                <span class="badge {_severity_class(incident.get('severity', ''))}">
                  {_esc(incident.get('severity'))}
                </span>
              </header>
              <p class="muted">{_esc(incident.get('incident_id'))}</p>
              <div class="grid-2">
                <div><strong>Risk Score</strong><div class="metric">{_esc(incident.get('risk_score'))}</div></div>
                <div><strong>Related Alerts</strong><div class="metric">{_esc(incident.get('alert_count'))}</div></div>
              </div>
              <p><strong>Source IPs:</strong> {_esc(', '.join(incident.get('source_ips') or []) or '-')}</p>
              <p><strong>Users:</strong> {_esc(', '.join(incident.get('usernames') or []) or '-')}</p>
              <p><strong>Observed Alert Chain:</strong> {chain_html}</p>
              <p><strong>First Seen:</strong> {_esc(incident.get('first_seen'))}</p>
              <p><strong>Last Seen:</strong> {_esc(incident.get('last_seen'))}</p>
              <p>{_esc(incident.get('description'))}</p>
              <details><summary>View Evidence</summary><pre>{_esc(evidence_json)}</pre></details>
            </article>
            """
        )

    sev_bars = []
    for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = alert_sev.get(label, 0)
        width = _bar_width(count, max_sev)
        sev_bars.append(
            f"<div class='bar-row'><span>{label}</span>"
            f"<div class='bar-track'><div class='bar-fill {_severity_class(label)}' "
            f"style='width:{width}%'></div></div>"
            f"<span>{count}</span></div>"
        )

    attack_bars = []
    for label, count in attack_types.items():
        width = _bar_width(count, max_attack)
        attack_bars.append(
            f"<div class='bar-row'><span>{_esc(label)}</span>"
            f"<div class='bar-track'><div class='bar-fill accent' "
            f"style='width:{width}%'></div></div>"
            f"<span>{count}</span></div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{_esc(meta.get('application'))} — Security Analysis Report</title>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: #121a2b;
      --panel-2: #182235;
      --text: #e8eefc;
      --muted: #9aa8c7;
      --accent: #3dd6c6;
      --border: #243049;
      --critical: #ff5c7a;
      --high: #ffb020;
      --medium: #5b8cff;
      --low: #6dd39a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Segoe UI, Tahoma, Geneva, Verdana, sans-serif;
      background: radial-gradient(circle at top, #152038 0%, var(--bg) 45%);
      color: var(--text);
      line-height: 1.45;
    }}
    .wrap {{ max-width: 1180px; margin: 0 auto; padding: 28px 18px 48px; }}
    h1, h2, h3 {{ margin: 0 0 10px; }}
    h1 {{ font-size: 1.8rem; letter-spacing: 0.04em; }}
    h2 {{ margin-top: 28px; font-size: 1.15rem; color: var(--accent); }}
    .subtitle {{ color: var(--muted); margin-bottom: 22px; }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      margin: 18px 0 8px;
    }}
    .card {{
      background: linear-gradient(180deg, var(--panel-2), var(--panel));
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
    }}
    .card .label {{ color: var(--muted); font-size: 0.82rem; }}
    .card .value {{ font-size: 1.55rem; font-weight: 700; margin-top: 6px; }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
      margin-top: 14px;
    }}
    .grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
    th, td {{ border-bottom: 1px solid var(--border); padding: 8px 6px; text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 700;
      border: 1px solid transparent;
    }}
    .sev-critical {{ background: rgba(255,92,122,.15); color: var(--critical); border-color: rgba(255,92,122,.35); }}
    .sev-high {{ background: rgba(255,176,32,.15); color: var(--high); border-color: rgba(255,176,32,.35); }}
    .sev-medium {{ background: rgba(91,140,255,.15); color: var(--medium); border-color: rgba(91,140,255,.35); }}
    .sev-low {{ background: rgba(109,211,154,.15); color: var(--low); border-color: rgba(109,211,154,.35); }}
    .bar-row {{ display: grid; grid-template-columns: 140px 1fr 40px; gap: 8px; align-items: center; margin: 6px 0; }}
    .bar-track {{ background: #0e1626; border-radius: 999px; height: 10px; overflow: hidden; }}
    .bar-fill {{ height: 100%; border-radius: 999px; background: var(--accent); }}
    .bar-fill.sev-critical {{ background: var(--critical); }}
    .bar-fill.sev-high {{ background: var(--high); }}
    .bar-fill.sev-medium {{ background: var(--medium); }}
    .bar-fill.sev-low {{ background: var(--low); }}
    .bar-fill.accent {{ background: var(--accent); }}
    .desc {{ max-width: 340px; }}
    details {{ margin-top: 6px; }}
    summary {{ cursor: pointer; color: var(--accent); }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      background: #0e1626;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px;
      color: #d5def3;
      font-size: 0.8rem;
    }}
    .incident-card {{
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-left: 4px solid var(--accent);
      border-radius: 10px;
      padding: 14px;
      margin-top: 12px;
    }}
    .incident-card header {{ display: flex; justify-content: space-between; gap: 10px; align-items: center; }}
    .muted {{ color: var(--muted); font-size: 0.85rem; }}
    .metric {{ font-size: 1.3rem; font-weight: 700; margin-top: 4px; }}
    .meta-list {{ color: var(--muted); font-size: 0.9rem; }}
    @media (max-width: 720px) {{
      .bar-row {{ grid-template-columns: 1fr; }}
      table {{ display: block; overflow-x: auto; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>{_esc(meta.get('application'))}</h1>
    <div class="subtitle">Security Analysis Report</div>

    <section class="cards">
      <div class="card"><div class="label">Events</div><div class="value">{_esc(summary.get('total_events'))}</div></div>
      <div class="card"><div class="label">Alerts</div><div class="value">{_esc(summary.get('total_alerts'))}</div></div>
      <div class="card"><div class="label">Incidents</div><div class="value">{_esc(summary.get('total_incidents'))}</div></div>
      <div class="card"><div class="label">Critical Alerts</div><div class="value">{_esc(summary.get('critical_alerts'))}</div></div>
      <div class="card"><div class="label">High Alerts</div><div class="value">{_esc(summary.get('high_alerts'))}</div></div>
      <div class="card"><div class="label">Highest Risk</div><div class="value">{_esc(summary.get('highest_risk_score'))}</div></div>
    </section>

    <h2>Log Overview</h2>
    <div class="panel grid-2">
      <div>
        <p><strong>Linux:</strong> {_esc(stats.get('linux_logs', 0))}</p>
        <p><strong>Windows:</strong> {_esc(stats.get('windows_logs', 0))}</p>
        <p><strong>Apache:</strong> {_esc(stats.get('apache_logs', 0))}</p>
      </div>
      <div>
        <p><strong>Successful Logins:</strong> {_esc(stats.get('successful_logins', 0))}</p>
        <p><strong>Failed Logins:</strong> {_esc(stats.get('failed_logins', 0))}</p>
        <p><strong>HTTP Requests:</strong> {_esc(stats.get('http_requests', 0))}</p>
      </div>
    </div>

    <h2>Security Overview</h2>
    <div class="panel grid-2">
      <div>
        <h3>Severity Distribution</h3>
        {''.join(sev_bars) if sev_bars else '<p class="muted">No alerts</p>'}
      </div>
      <div>
        <h3>Attack Type Distribution</h3>
        {''.join(attack_bars) if attack_bars else '<p class="muted">No attack types</p>'}
      </div>
    </div>

    <h2>Timeline</h2>
    <div class="panel">
      <table>
        <thead><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>IP</th><th>User</th></tr></thead>
        <tbody>
          {''.join(timeline_rows) if timeline_rows else '<tr><td colspan="5">No alerts</td></tr>'}
        </tbody>
      </table>
    </div>

    <h2>Top Source IPs / Users</h2>
    <div class="panel grid-2">
      <div>
        <h3>Top Source IP</h3>
        <p>{_esc(top_ip_label)} — {_esc(top_ip_count)} events</p>
        <p class="muted">Unique IPs: {_esc(stats.get('unique_ips', 0))}</p>
      </div>
      <div>
        <h3>Top User</h3>
        <p>{_esc(top_user_label)} — {_esc(top_user_count)} events</p>
        <p class="muted">Unique Users: {_esc(stats.get('unique_users', 0))}</p>
      </div>
    </div>

    <h2>Security Alerts</h2>
    <div class="panel">
      <table>
        <thead>
          <tr>
            <th>Severity</th><th>Type</th><th>Timestamp</th><th>User</th>
            <th>IP</th><th>Confidence</th><th>Risk</th><th>Description</th>
          </tr>
        </thead>
        <tbody>
          {''.join(alert_rows) if alert_rows else '<tr><td colspan="8">No alerts</td></tr>'}
        </tbody>
      </table>
    </div>

    <h2>Security Incidents</h2>
    <div class="panel">
      {''.join(incident_cards) if incident_cards else '<p class="muted">No incidents</p>'}
    </div>

    <h2>Report Metadata</h2>
    <div class="panel meta-list">
      <p><strong>Application:</strong> {_esc(meta.get('application'))}</p>
      <p><strong>Version:</strong> {_esc(meta.get('analyzer_version'))}</p>
      <p><strong>Input File:</strong> {_esc(meta.get('input_file'))}</p>
      <p><strong>Analyzed At:</strong> {_esc(analysis.get('analyzed_at'))}</p>
      <p><strong>Duration:</strong> {_esc(analysis.get('duration_seconds'))} seconds</p>
      <p><strong>Report Generated:</strong> {_esc(meta.get('report_generated_at'))}</p>
      <p><strong>Parsed / Malformed / Unsupported:</strong>
        {_esc(analysis.get('parsed_lines'))} /
        {_esc(analysis.get('malformed_lines'))} /
        {_esc(analysis.get('unsupported_lines'))}
      </p>
    </div>
  </div>
</body>
</html>
"""


def write_html_report(result: AnalysisResult, output_dir: Path) -> Path:
    """Write standalone ``security_report.html`` and return the path."""
    output_dir = Path(output_dir)
    path = output_dir / "security_report.html"
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        document = build_report_document(result)
        path.write_text(_render_html(document), encoding="utf-8")
        return path
    except OSError as exc:
        raise ReportGenerationError(f"Unable to write HTML report: {exc}") from exc
