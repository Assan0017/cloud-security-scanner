"""Builds an HTML risk report from findings, with an overall risk score,
and optionally exports it to PDF (needs wkhtmltopdf/weasyprint - optional).
"""
import os
from datetime import datetime
from collections import Counter
from rules import Severity

SEVERITY_COLOR = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#65a30d",
}


def compute_risk_score(findings) -> dict:
    total = sum(f.score for f in findings)
    counts = Counter(f.severity for f in findings)
    # Normalize to a 0-100 scale, capped, so the number is stable across scan sizes
    max_reasonable = 200
    normalized = min(100, round((total / max_reasonable) * 100)) if total else 0
    if normalized >= 70:
        grade = "CRITICAL RISK"
    elif normalized >= 40:
        grade = "HIGH RISK"
    elif normalized >= 15:
        grade = "MODERATE RISK"
    else:
        grade = "LOW RISK"
    return {
        "raw_score": total,
        "normalized": normalized,
        "grade": grade,
        "counts": counts,
    }


def generate_html_report(findings, account_id: str, output_path: str) -> str:
    risk = compute_risk_score(findings)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    findings_sorted = sorted(findings, key=lambda f: -f.score)

    rows = "\n".join(_finding_row(f) for f in findings_sorted) or \
        "<tr><td colspan='5' style='text-align:center;padding:20px;'>No findings — clean scan 🎉</td></tr>"

    summary_cards = "".join(
        f"""<div class="stat-card" style="border-color:{SEVERITY_COLOR[sev]}">
              <div class="stat-num" style="color:{SEVERITY_COLOR[sev]}">{risk['counts'].get(sev, 0)}</div>
              <div class="stat-label">{sev.value}</div>
            </div>"""
        for sev in Severity
    )

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Cloud Security Posture Report</title>
<style>
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:32px; }}
  h1 {{ margin-bottom:4px; }}
  .meta {{ color:#94a3b8; margin-bottom:24px; font-size:0.9rem; }}
  .risk-banner {{ padding:20px; border-radius:12px; background:#1e293b; border:1px solid #334155; margin-bottom:24px; }}
  .risk-grade {{ font-size:1.6rem; font-weight:800; }}
  .risk-bar-bg {{ background:#0f172a; border-radius:6px; height:14px; margin-top:10px; overflow:hidden; }}
  .risk-bar {{ height:100%; background:linear-gradient(90deg,#22c55e,#eab308,#dc2626); width:{risk['normalized']}%; }}
  .stats {{ display:flex; gap:16px; margin-bottom:28px; flex-wrap:wrap; }}
  .stat-card {{ background:#1e293b; border:2px solid; border-radius:10px; padding:14px 20px; text-align:center; min-width:110px; }}
  .stat-num {{ font-size:1.8rem; font-weight:800; }}
  .stat-label {{ font-size:0.75rem; color:#94a3b8; letter-spacing:0.05em; }}
  table {{ width:100%; border-collapse:collapse; background:#1e293b; border-radius:10px; overflow:hidden; }}
  th, td {{ padding:10px 14px; text-align:left; border-bottom:1px solid #334155; font-size:0.85rem; vertical-align:top; }}
  th {{ background:#334155; color:#f1f5f9; }}
  .sev-badge {{ display:inline-block; padding:2px 10px; border-radius:12px; font-size:0.72rem; font-weight:700; color:#0f172a; }}
  .remediation {{ color:#93c5fd; }}
  footer {{ margin-top:28px; color:#64748b; font-size:0.75rem; }}
</style>
</head>
<body>
  <h1>☁️ Cloud Security Posture Report</h1>
  <div class="meta">AWS Account: {account_id} &nbsp;•&nbsp; Generated {now}</div>

  <div class="risk-banner">
    <div class="risk-grade" style="color:{_grade_color(risk['grade'])}">{risk['grade']} — score {risk['normalized']}/100</div>
    <div class="risk-bar-bg"><div class="risk-bar"></div></div>
  </div>

  <div class="stats">{summary_cards}</div>

  <table>
    <tr><th>Severity</th><th>Rule</th><th>Resource</th><th>Detail</th><th>Remediation</th></tr>
    {rows}
  </table>

  <footer>Rules mapped to the CIS AWS Foundations Benchmark (public, free reference). This report is generated for portfolio/educational use.</footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


def _grade_color(grade: str) -> str:
    return {
        "CRITICAL RISK": "#dc2626", "HIGH RISK": "#ea580c",
        "MODERATE RISK": "#d97706", "LOW RISK": "#65a30d",
    }[grade]


def _finding_row(f) -> str:
    color = SEVERITY_COLOR[f.severity]
    return f"""<tr>
      <td><span class="sev-badge" style="background:{color}">{f.severity.value}</span></td>
      <td>{f.rule_id}<br><small style="color:#94a3b8">{f.cis_control}</small></td>
      <td>{f.resource}</td>
      <td>{f.detail}</td>
      <td class="remediation">{f.remediation}</td>
    </tr>"""


def export_pdf(html_path: str, pdf_path: str) -> bool:
    """Best-effort PDF export. Returns True on success, False if no PDF
    backend is installed (HTML report is still perfectly usable on its own)."""
    try:
        from weasyprint import HTML
        HTML(html_path).write_pdf(pdf_path)
        return True
    except Exception:
        return False
