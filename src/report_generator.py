import html
from datetime import datetime
from typing import Dict, Any, List


def generate_executive_html_report(incident_data: Dict[str, Any]) -> str:
    """
    Generates a professional, branded Executive Security Incident Report (HTML)
    with CVSS-style threat grading and an actionable SOC Remediation Playbook.
    """
    incident_id = incident_data.get("incident_id", f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    timestamp = incident_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    target = incident_data.get("target", "Unknown Target")
    scan_type = incident_data.get("type", "General Threat Scan")
    score = incident_data.get("risk_score", 0)
    verdict = incident_data.get("verdict", "INCONCLUSIVE")
    red_flags = incident_data.get("red_flags", [])
    recommendations = incident_data.get("recommendations", [])

    # Color mapping
    if score >= 70:
        badge_color = "#DC2626"
        badge_bg = "#FEE2E2"
        rating = "CRITICAL / HIGH SEVERITY"
    elif score >= 40:
        badge_color = "#D97706"
        badge_bg = "#FEF3C7"
        rating = "MEDIUM / SUSPICIOUS"
    else:
        badge_color = "#16A34A"
        badge_bg = "#DCFCE7"
        rating = "LOW / BENIGN"

    # Default SOC playbook recommendations if none provided
    if not recommendations:
        if score >= 70:
            recommendations = [
                "Containment: Implement immediate domain/IP block on Perimeter Firewalls and Secure Web Gateways (SWG).",
                "Identity Defense: If credentials were typed, force immediate global session revocation and reset password + MFA tokens.",
                "Mailbox Search & Destroy: Initiate an administrative tenant-wide search for identical envelope senders and purge from all mailboxes.",
                "Threat Intel Escalation: Submit malicious FQDN/URL to corporate SIEM/EDR blocklists and upstream threat feeds."
            ]
        elif score >= 40:
            recommendations = [
                "Precautionary Monitoring: Flag sending domain in E-mail Security Gateway (SEG) for manual inspection.",
                "User Awareness: Educate recipient about urgency triggers and suspicious link patterns.",
                "Endpoint Verification: Verify endpoint telemetry for browser downloads or redirected authentication prompts."
            ]
        else:
            recommendations = [
                "Standard Policy: No immediate containment required. Normal security hygiene applies.",
                "Whitelisting: Verify corporate domain alignment before adding to trusted sender rosters."
            ]

    flags_html = "".join([f"<li style='margin-bottom:6px;'><strong>🚩 Flag:</strong> {html.escape(f)}</li>" for f in red_flags]) or "<li>No critical security red flags triggered.</li>"
    recs_html = "".join([f"<li style='margin-bottom:8px;'><strong>Action:</strong> {html.escape(r)}</li>" for r in recommendations])

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PhishGuard Security Incident Report - {incident_id}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #F8FAFC;
            color: #1E293B;
            margin: 0;
            padding: 30px;
        }}
        .report-card {{
            max-width: 820px;
            margin: 0 auto;
            background: #FFFFFF;
            border: 1px solid #E2E8F0;
            border-radius: 12px;
            padding: 36px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.06);
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #E2E8F0;
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}
        .logo {{
            font-size: 22px;
            font-weight: 800;
            color: #0F172A;
        }}
        .badge {{
            padding: 6px 14px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 13px;
            background-color: {badge_bg};
            color: {badge_color};
            border: 1px solid {badge_color};
        }}
        .metric-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-bottom: 28px;
        }}
        .metric-box {{
            background: #F1F5F9;
            padding: 14px;
            border-radius: 8px;
            text-align: center;
        }}
        .metric-val {{
            font-size: 24px;
            font-weight: 800;
            color: #0F172A;
            margin-top: 4px;
        }}
        .metric-label {{
            font-size: 11px;
            font-weight: 600;
            color: #64748B;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        h2 {{
            font-size: 16px;
            font-weight: 700;
            color: #0F172A;
            border-left: 4px solid #3B82F6;
            padding-left: 10px;
            margin-top: 24px;
            margin-bottom: 12px;
        }}
        ul {{
            padding-left: 20px;
            line-height: 1.6;
            font-size: 13px;
        }}
        .footer {{
            margin-top: 36px;
            border-top: 1px solid #E2E8F0;
            padding-top: 14px;
            font-size: 11px;
            color: #94A3B8;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="report-card">
        <div class="header">
            <div class="logo">🛡️ PhishGuard AI <span style="font-size:14px; font-weight:500; color:#64748B;">| Threat Intelligence Report</span></div>
            <div class="badge">{rating}</div>
        </div>

        <div class="metric-grid">
            <div class="metric-box">
                <div class="metric-label">Incident Reference</div>
                <div class="metric-val" style="font-size:16px; font-family:monospace;">{incident_id}</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">Risk Severity Score</div>
                <div class="metric-val" style="color:{badge_color};">{score}/100</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">Evaluation Verdict</div>
                <div class="metric-val" style="font-size:14px;">{html.escape(verdict)}</div>
            </div>
        </div>

        <h2>Target Inspection Artifact</h2>
        <p style="font-family:monospace; background:#F8FAFC; padding:10px; border-radius:6px; font-size:12px; word-break:break-all;">
            {html.escape(str(target))}
        </p>

        <h2>Identified Threat Indicators (IOCs)</h2>
        <ul>
            {flags_html}
        </ul>

        <h2>SOC Incident Response Playbook & Recommended Actions</h2>
        <ul style="color:#0F172A;">
            {recs_html}
        </ul>

        <div class="footer">
            Generated automatically by PhishGuard Enterprise AI Platform • Timestamp: {timestamp} • Confidential Threat Advisory
        </div>
    </div>
</body>
</html>
"""
    return report_html
