from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import BaseLoader, Environment

from scanner.report.models import ScanReport

SEVERITY_COLORS = {
    "Critical": "#e74c3c",
    "High": "#e67e22",
    "Medium": "#f1c40f",
    "Low": "#3498db",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Scan Report — {{ report.target_url }}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 2rem; }
    h1 { color: #e0e0e0; }
    .meta { color: #aaa; margin-bottom: 2rem; font-size: 0.95rem; }
    .summary { display: flex; gap: 1rem; margin-bottom: 2rem; }
    .badge { padding: 0.5rem 1rem; border-radius: 6px; font-weight: bold; color: #fff; }
    table { width: 100%; border-collapse: collapse; background: #16213e; border-radius: 8px; overflow: hidden; }
    th { background: #0f3460; color: #e0e0e0; padding: 0.75rem 1rem; text-align: left; }
    td { padding: 0.75rem 1rem; border-bottom: 1px solid #2a2a4a; font-size: 0.9rem; word-break: break-all; }
    tr:last-child td { border-bottom: none; }
    .sev { font-weight: bold; }
  </style>
</head>
<body>
<h1>🔍 Scan Report</h1>
<div class="meta">
  <strong>Target:</strong> {{ report.target_url }}<br>
  <strong>Started:</strong> {{ report.started_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}<br>
  {% if report.duration_seconds is not none %}
  <strong>Duration:</strong> {{ "%.1f"|format(report.duration_seconds) }}s
  {% endif %}
</div>
<div class="summary">
  <span class="badge" style="background:#e74c3c">Critical: {{ report.critical_count }}</span>
  <span class="badge" style="background:#e67e22">High: {{ report.high_count }}</span>
  <span class="badge" style="background:#f1c40f; color:#333">Medium: {{ report.medium_count }}</span>
  <span class="badge" style="background:#3498db">Low: {{ report.low_count }}</span>
</div>
{% if findings %}
<table>
  <thead>
    <tr>
      <th>Severity</th><th>Module</th><th>Title</th>
      <th>URL</th><th>Evidence</th><th>Remediation</th>
    </tr>
  </thead>
  <tbody>
  {% for f in findings %}
    <tr>
      <td class="sev" style="color:{{ colors[f.severity.value] }}">{{ f.severity.value }}</td>
      <td>{{ f.module }}</td>
      <td>{{ f.title }}</td>
      <td>{{ f.url }}</td>
      <td>{{ f.evidence }}</td>
      <td>{{ f.remediation }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p>✅ No findings.</p>
{% endif %}
</body>
</html>"""


def export_json(report: ScanReport, path: str) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    data = report.model_dump(mode="json")
    out.write_text(json.dumps(data, indent=2, default=str))


def export_html(report: ScanReport, path: str) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    sorted_findings = sorted(report.findings, key=lambda f: f.severity, reverse=True)
    env = Environment(loader=BaseLoader())
    template = env.from_string(HTML_TEMPLATE)
    html = template.render(
        report=report,
        findings=sorted_findings,
        colors=SEVERITY_COLORS,
    )
    out.write_text(html)
