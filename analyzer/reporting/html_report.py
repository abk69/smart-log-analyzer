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
    if maximum <= 0 or count <= 0:
        return 0
    return max(6, int((count / maximum) * 100))


def _pct(count: int, total: int) -> str:
    if total <= 0:
        return "0%"
    return f"{(count / total) * 100:.0f}%"


def _risk_class(score: object) -> str:
    try:
        value = int(score or 0)
    except (TypeError, ValueError):
        value = 0
    if value >= 90:
        return "risk-critical"
    if value >= 70:
        return "risk-high"
    if value >= 40:
        return "risk-medium"
    return "risk-low"


def _executive_sentence(summary: dict) -> str:
    alerts = int(summary.get("total_alerts") or 0)
    incidents = int(summary.get("total_incidents") or 0)
    critical = int(summary.get("critical_alerts") or 0)
    high = int(summary.get("high_alerts") or 0)

    if alerts == 0:
        return "Analysis completed with no security alerts detected."

    parts = [
        f"Analysis identified {alerts} security alert"
        f"{'s' if alerts != 1 else ''}"
        f" across {incidents} correlated incident"
        f"{'s' if incidents != 1 else ''}"
    ]
    if critical or high:
        detail = []
        if critical:
            detail.append(f"{critical} critical")
        if high:
            detail.append(f"{high} high")
        parts.append(", including " + " and ".join(detail) + " alert" + ("s" if (critical + high) != 1 else ""))
    return "".join(parts) + "."


def _mini_metric(label: str, value: object) -> str:
    return (
        f"<div class='mini-metric'><span class='mini-label'>{_esc(label)}</span>"
        f"<span class='mini-value'>{_esc(value)}</span></div>"
    )


def _render_html(document: dict) -> str:
    meta = document["metadata"]
    analysis = document["analysis"]
    stats = document["statistics"]
    summary = document["summary"]
    alerts = document["alerts"]
    incidents = document["incidents"]

    alert_sev = summary["alert_severity"]
    attack_types = summary["attack_types"]
    total_alerts = int(summary.get("total_alerts") or 0)
    max_sev = max(alert_sev.values()) if alert_sev else 0
    max_attack = max(attack_types.values()) if attack_types else 0

    top_ip = stats.get("top_ip", ("-", 0))
    top_user = stats.get("top_user", ("-", 0))
    if isinstance(top_ip, (list, tuple)) and len(top_ip) == 2:
        top_ip_label, top_ip_count = top_ip[0], top_ip[1]
    else:
        top_ip_label, top_ip_count = "-", 0
    if isinstance(top_user, (list, tuple)) and len(top_user) == 2:
        top_user_label, top_user_count = top_user[0], top_user[1]
    else:
        top_user_label, top_user_count = "-", 0

    duration = analysis.get("duration_seconds", 0)
    try:
        duration_label = f"{float(duration):.2f}s"
    except (TypeError, ValueError):
        duration_label = str(duration)

    executive = _executive_sentence(summary)

    timeline_rows = []
    for alert in sorted(alerts, key=lambda a: a.get("timestamp") or ""):
        timeline_rows.append(
            "<tr>"
            f"<td class='nowrap'>{_esc(alert.get('timestamp'))}</td>"
            f"<td><span class='badge {_severity_class(alert.get('severity', ''))}'>"
            f"{_esc(alert.get('alert_type'))}</span></td>"
            f"<td><span class='badge {_severity_class(alert.get('severity', ''))}'>"
            f"{_esc(alert.get('severity'))}</span></td>"
            f"<td class='mono'>{_esc(alert.get('ip_address'))}</td>"
            f"<td>{_esc(alert.get('username'))}</td>"
            "</tr>"
        )

    alert_rows = []
    for alert in alerts:
        evidence_json = json.dumps(alert.get("evidence", {}), indent=2, ensure_ascii=False)
        risk = alert.get("risk_score", 0)
        alert_rows.append(
            "<tr>"
            f"<td><span class='badge {_severity_class(alert.get('severity', ''))}'>"
            f"{_esc(alert.get('severity'))}</span></td>"
            f"<td class='type-cell'>{_esc(alert.get('alert_type'))}</td>"
            f"<td class='nowrap'>{_esc(alert.get('timestamp'))}</td>"
            f"<td>{_esc(alert.get('username'))}</td>"
            f"<td class='mono'>{_esc(alert.get('ip_address'))}</td>"
            f"<td>{_esc(alert.get('confidence'))}</td>"
            f"<td><span class='risk-badge {_risk_class(risk)}'>{_esc(risk)}</span></td>"
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
        if chain:
            chain_html = "<ol class='chain'>" + "".join(
                f"<li>{_esc(step)}</li>" for step in chain
            ) + "</ol>"
        else:
            chain_html = "<span class='muted'>N/A</span>"
        evidence_json = json.dumps(incident.get("evidence", {}), indent=2, ensure_ascii=False)
        risk = incident.get("risk_score", 0)
        incident_cards.append(
            f"""
            <article class="incident-card">
              <header>
                <div>
                  <div class="incident-kicker">Correlated Incident</div>
                  <h3>INCIDENT-{index:03d}</h3>
                  <div class="muted mono">{_esc(incident.get('incident_id'))}</div>
                </div>
                <div class="incident-badges">
                  <span class="badge {_severity_class(incident.get('severity', ''))}">
                    {_esc(incident.get('severity'))}
                  </span>
                  <span class="risk-badge {_risk_class(risk)}">Risk {_esc(risk)}</span>
                </div>
              </header>
              <div class="incident-stats">
                <div><span class="mini-label">Related Alerts</span><span class="mini-value">{_esc(incident.get('alert_count'))}</span></div>
                <div><span class="mini-label">First Seen</span><span class="mini-value small">{_esc(incident.get('first_seen'))}</span></div>
                <div><span class="mini-label">Last Seen</span><span class="mini-value small">{_esc(incident.get('last_seen'))}</span></div>
              </div>
              <div class="incident-body">
                <p><strong>Source IPs</strong><br/>{_esc(', '.join(incident.get('source_ips') or []) or '-')}</p>
                <p><strong>Users</strong><br/>{_esc(', '.join(incident.get('usernames') or []) or '-')}</p>
                <p><strong>Observed Alert Chain</strong></p>
                {chain_html}
                <p class="incident-desc">{_esc(incident.get('description'))}</p>
                <details><summary>View Evidence</summary><pre>{_esc(evidence_json)}</pre></details>
              </div>
            </article>
            """
        )

    sev_bars = []
    for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = alert_sev.get(label, 0)
        width = _bar_width(count, max_sev)
        sev_bars.append(
            "<div class='bar-row'>"
            f"<span class='bar-label'><span class='badge {_severity_class(label)}'>{label}</span></span>"
            f"<div class='bar-track'><div class='bar-fill {_severity_class(label)}' style='width:{width}%'></div></div>"
            f"<span class='bar-meta'>{count} <span class='muted'>({_pct(count, total_alerts)})</span></span>"
            "</div>"
        )

    attack_bars = []
    for label, count in attack_types.items():
        width = _bar_width(count, max_attack)
        attack_bars.append(
            "<div class='bar-row'>"
            f"<span class='bar-label mono'>{_esc(label)}</span>"
            f"<div class='bar-track'><div class='bar-fill accent' style='width:{width}%'></div></div>"
            f"<span class='bar-meta'>{count} <span class='muted'>({_pct(count, total_alerts)})</span></span>"
            "</div>"
        )

    log_metrics = "".join(
        [
            _mini_metric("Linux", stats.get("linux_logs", 0)),
            _mini_metric("Windows", stats.get("windows_logs", 0)),
            _mini_metric("Apache", stats.get("apache_logs", 0)),
            _mini_metric("Successful Logins", stats.get("successful_logins", 0)),
            _mini_metric("Failed Logins", stats.get("failed_logins", 0)),
            _mini_metric("HTTP Requests", stats.get("http_requests", 0)),
            _mini_metric("Unique Users", stats.get("unique_users", 0)),
            _mini_metric("Unique IPs", stats.get("unique_ips", 0)),
        ]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{_esc(meta.get('application'))} — Security Analysis Report</title>
  <style>
    :root {{
      --bg: #070d18;
      --panel: #101826;
      --panel-2: #152033;
      --text: #edf2ff;
      --muted: #93a0bd;
      --accent: #2fd6c3;
      --accent-2: #6ea8ff;
      --border: #243149;
      --critical: #ff5c7a;
      --high: #ffb020;
      --medium: #5b8cff;
      --low: #6dd39a;
      --shadow: 0 10px 30px rgba(0,0,0,.28);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      background:
        radial-gradient(1200px 500px at 10% -10%, rgba(47,214,195,.12), transparent 55%),
        radial-gradient(900px 400px at 90% 0%, rgba(110,168,255,.10), transparent 50%),
        var(--bg);
      color: var(--text);
      line-height: 1.4;
      font-size: 14px;
    }}
    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 22px 16px 40px; }}
    .hero {{
      border: 1px solid var(--border);
      background: linear-gradient(180deg, rgba(21,32,51,.95), rgba(16,24,38,.95));
      border-radius: 14px;
      padding: 18px 18px 14px;
      box-shadow: var(--shadow);
    }}
    .eyebrow {{
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: .12em;
      font-size: .72rem;
      font-weight: 700;
      margin-bottom: 6px;
    }}
    h1 {{
      margin: 0;
      font-size: 1.7rem;
      letter-spacing: .03em;
      font-weight: 750;
    }}
    .subtitle {{
      margin: 4px 0 12px;
      color: var(--muted);
      font-size: .95rem;
    }}
    .meta-row {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 8px;
      margin-top: 8px;
    }}
    .meta-chip {{
      background: rgba(7,13,24,.55);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 8px 10px;
      min-width: 0;
    }}
    .meta-chip .k {{ display:block; color: var(--muted); font-size: .72rem; margin-bottom: 2px; }}
    .meta-chip .v {{ display:block; font-weight: 650; font-size: .86rem; word-break: break-word; }}
    h2 {{
      margin: 22px 0 8px;
      font-size: 1.02rem;
      color: var(--accent);
      letter-spacing: .04em;
      text-transform: uppercase;
    }}
    h3 {{
      margin: 0 0 8px;
      font-size: .92rem;
      color: var(--text);
      font-weight: 700;
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 10px;
      margin: 14px 0 0;
    }}
    .card {{
      background: linear-gradient(180deg, #182337, #121c2d);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px;
      box-shadow: var(--shadow);
      position: relative;
      overflow: hidden;
    }}
    .card::before {{
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 3px;
      background: var(--accent);
    }}
    .card.critical::before {{ background: var(--critical); }}
    .card.high::before {{ background: var(--high); }}
    .card.risk::before {{ background: var(--accent-2); }}
    .card .label {{ color: var(--muted); font-size: .74rem; text-transform: uppercase; letter-spacing: .04em; }}
    .card .value {{ font-size: 1.45rem; font-weight: 750; margin-top: 6px; }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px 14px;
      margin-top: 8px;
      box-shadow: var(--shadow);
    }}
    .exec {{
      display: grid;
      grid-template-columns: 1.1fr 1.6fr;
      gap: 12px;
      align-items: stretch;
    }}
    .posture-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
    }}
    .posture-item {{
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px;
    }}
    .posture-item .k {{ color: var(--muted); font-size: .75rem; }}
    .posture-item .v {{ font-size: 1.15rem; font-weight: 750; margin-top: 2px; }}
    .exec-copy {{
      background: linear-gradient(135deg, rgba(47,214,195,.08), rgba(110,168,255,.06));
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px 14px;
      color: #dce6ff;
      font-size: .95rem;
    }}
    .mini-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 8px;
    }}
    .mini-metric {{
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 9px 10px;
    }}
    .mini-label {{ display:block; color: var(--muted); font-size: .72rem; margin-bottom: 3px; }}
    .mini-value {{ display:block; font-size: 1.05rem; font-weight: 720; }}
    .mini-value.small {{ font-size: .82rem; font-weight: 600; }}
    .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: .86rem; }}
    th, td {{ border-bottom: 1px solid var(--border); padding: 7px 6px; text-align: left; vertical-align: top; }}
    th {{
      color: var(--muted);
      font-weight: 700;
      font-size: .74rem;
      text-transform: uppercase;
      letter-spacing: .04em;
      background: #0d1524;
      position: sticky;
      top: 0;
      z-index: 1;
    }}
    tbody tr:hover {{ background: rgba(255,255,255,.02); }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: .70rem;
      font-weight: 750;
      border: 1px solid transparent;
      white-space: nowrap;
    }}
    .risk-badge {{
      display: inline-block;
      min-width: 42px;
      text-align: center;
      padding: 2px 8px;
      border-radius: 8px;
      font-size: .75rem;
      font-weight: 750;
      border: 1px solid transparent;
    }}
    .sev-critical, .risk-critical {{ background: rgba(255,92,122,.15); color: var(--critical); border-color: rgba(255,92,122,.35); }}
    .sev-high, .risk-high {{ background: rgba(255,176,32,.15); color: var(--high); border-color: rgba(255,176,32,.35); }}
    .sev-medium, .risk-medium {{ background: rgba(91,140,255,.15); color: var(--medium); border-color: rgba(91,140,255,.35); }}
    .sev-low, .risk-low {{ background: rgba(109,211,154,.15); color: var(--low); border-color: rgba(109,211,154,.35); }}
    .bar-row {{
      display: grid;
      grid-template-columns: 128px 1fr 78px;
      gap: 8px;
      align-items: center;
      margin: 7px 0;
    }}
    .bar-label {{ overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .bar-track {{ background: #0a1220; border-radius: 999px; height: 9px; overflow: hidden; border: 1px solid #1b2740; }}
    .bar-fill {{ height: 100%; border-radius: 999px; background: var(--accent); }}
    .bar-fill.sev-critical {{ background: var(--critical); }}
    .bar-fill.sev-high {{ background: var(--high); }}
    .bar-fill.sev-medium {{ background: var(--medium); }}
    .bar-fill.sev-low {{ background: var(--low); }}
    .bar-fill.accent {{ background: linear-gradient(90deg, var(--accent), var(--accent-2)); }}
    .bar-meta {{ text-align: right; font-size: .82rem; white-space: nowrap; }}
    .desc {{ max-width: 320px; }}
    .type-cell {{ font-weight: 650; }}
    .nowrap {{ white-space: nowrap; }}
    .mono {{ font-family: Consolas, "Courier New", monospace; font-size: .84rem; }}
    details {{ margin-top: 6px; }}
    summary {{ cursor: pointer; color: var(--accent); font-size: .82rem; }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      background: #0a1220;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px;
      color: #d5def3;
      font-size: .78rem;
      margin: 6px 0 0;
    }}
    .incident-card {{
      background: linear-gradient(180deg, #172338, #121c2e);
      border: 1px solid #2b3c5d;
      border-left: 5px solid var(--accent);
      border-radius: 12px;
      padding: 14px;
      margin-top: 10px;
      box-shadow: var(--shadow);
    }}
    .incident-card header {{ display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; }}
    .incident-kicker {{
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: .08em;
      font-size: .68rem;
      font-weight: 750;
      margin-bottom: 2px;
    }}
    .incident-badges {{ display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end; }}
    .incident-stats {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
      margin: 10px 0;
    }}
    .incident-stats > div {{
      background: rgba(7,13,24,.45);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px;
    }}
    .incident-body p {{ margin: 8px 0; }}
    .incident-desc {{ color: #d7e0f5; }}
    .chain {{
      margin: 6px 0 0 18px;
      padding: 0;
      color: #dce6ff;
    }}
    .chain li {{ margin: 2px 0; }}
    .muted {{ color: var(--muted); }}
    .top-box {{
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 12px;
    }}
    .top-box .value {{ font-size: 1.05rem; font-weight: 720; margin: 4px 0; }}
    .meta-list {{ color: var(--muted); font-size: .88rem; }}
    .meta-list p {{ margin: 6px 0; }}
    @media (max-width: 980px) {{
      .cards {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
      .meta-row, .mini-grid, .exec, .grid-2, .incident-stats {{ grid-template-columns: 1fr 1fr; }}
    }}
    @media (max-width: 640px) {{
      .cards, .meta-row, .mini-grid, .exec, .grid-2, .incident-stats {{ grid-template-columns: 1fr; }}
      .bar-row {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <header class="hero">
      <div class="eyebrow">Security Operations Report</div>
      <h1>{_esc(meta.get('application'))}</h1>
      <div class="subtitle">Security Analysis Report</div>
      <div class="meta-row">
        <div class="meta-chip"><span class="k">Input File</span><span class="v">{_esc(meta.get('input_file'))}</span></div>
        <div class="meta-chip"><span class="k">Analyzed At</span><span class="v">{_esc(analysis.get('analyzed_at'))}</span></div>
        <div class="meta-chip"><span class="k">Duration</span><span class="v">{_esc(duration_label)}</span></div>
        <div class="meta-chip"><span class="k">Total Events</span><span class="v">{_esc(summary.get('total_events'))}</span></div>
      </div>
    </header>

    <h2>Executive Summary</h2>
    <div class="panel exec">
      <div>
        <h3>Security Posture</h3>
        <div class="posture-grid">
          <div class="posture-item"><div class="k">Critical Alerts</div><div class="v">{_esc(summary.get('critical_alerts'))}</div></div>
          <div class="posture-item"><div class="k">High Alerts</div><div class="v">{_esc(summary.get('high_alerts'))}</div></div>
          <div class="posture-item"><div class="k">Total Incidents</div><div class="v">{_esc(summary.get('total_incidents'))}</div></div>
          <div class="posture-item"><div class="k">Highest Risk</div><div class="v">{_esc(summary.get('highest_risk_score'))}</div></div>
        </div>
      </div>
      <div class="exec-copy">
        <h3>Assessment</h3>
        <p>{_esc(executive)}</p>
      </div>
    </div>

    <h2>Key Metrics</h2>
    <section class="cards">
      <div class="card"><div class="label">Total Events</div><div class="value">{_esc(summary.get('total_events'))}</div></div>
      <div class="card"><div class="label">Alerts</div><div class="value">{_esc(summary.get('total_alerts'))}</div></div>
      <div class="card"><div class="label">Incidents</div><div class="value">{_esc(summary.get('total_incidents'))}</div></div>
      <div class="card critical"><div class="label">Critical Alerts</div><div class="value">{_esc(summary.get('critical_alerts'))}</div></div>
      <div class="card high"><div class="label">High Alerts</div><div class="value">{_esc(summary.get('high_alerts'))}</div></div>
      <div class="card risk"><div class="label">Highest Risk</div><div class="value">{_esc(summary.get('highest_risk_score'))}</div></div>
    </section>

    <h2>Log Overview</h2>
    <div class="panel">
      <div class="mini-grid">
        {log_metrics}
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
    <div class="panel table-wrap">
      <table>
        <thead><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>IP</th><th>User</th></tr></thead>
        <tbody>
          {''.join(timeline_rows) if timeline_rows else '<tr><td colspan="5">No alerts</td></tr>'}
        </tbody>
      </table>
    </div>

    <h2>Top Source IPs / Users</h2>
    <div class="panel grid-2">
      <div class="top-box">
        <h3>Top Source IP</h3>
        <div class="value mono">{_esc(top_ip_label)}</div>
        <div class="muted">{_esc(top_ip_count)} events · Unique IPs: {_esc(stats.get('unique_ips', 0))}</div>
      </div>
      <div class="top-box">
        <h3>Top User</h3>
        <div class="value">{_esc(top_user_label)}</div>
        <div class="muted">{_esc(top_user_count)} events · Unique Users: {_esc(stats.get('unique_users', 0))}</div>
      </div>
    </div>

    <h2>Security Alerts</h2>
    <div class="panel table-wrap">
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
      <p><strong>Duration:</strong> {_esc(duration_label)}</p>
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
