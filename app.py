import streamlit as st
import sys
import os
import pandas as pd
import json
from datetime import datetime

# Setup paths
SRC_DIR = os.path.join(os.path.dirname(__file__), "src")
sys.path.insert(0, SRC_DIR)

from predictor import PhishingDetector
from train import train_all, train_url_model, train_email_model
from xai_highlighter import highlight_email_threat_cues
from quishing import analyze_quishing_threat
from report_generator import generate_executive_html_report

st.set_page_config(
    page_title="PhishGuard Enterprise AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Session State for Incident Audit History
if "audit_history" not in st.session_state:
    st.session_state.audit_history = []

# Custom Styling (Dark/Light Cyber Modern UI)
st.markdown("""
<style>
    .main-header {
        font-size: 2.3rem;
        font-weight: 800;
        color: #0F172A;
        letter-spacing: -0.5px;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        color: #475569;
        font-size: 1.05rem;
        margin-bottom: 1.5rem;
    }
    .badge-danger {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 6px 14px;
        border-radius: 20px;
        font-weight: 700;
        display: inline-block;
        border: 1px solid #F87171;
    }
    .badge-warning {
        background-color: #FEF3C7;
        color: #92400E;
        padding: 6px 14px;
        border-radius: 20px;
        font-weight: 700;
        display: inline-block;
        border: 1px solid #FBBF24;
    }
    .badge-success {
        background-color: #DCFCE7;
        color: #166534;
        padding: 6px 14px;
        border-radius: 20px;
        font-weight: 700;
        display: inline-block;
        border: 1px solid #4ADE80;
    }
    .xai-box {
        background-color: #F8FAFC;
        border: 1px solid #CBD5E1;
        border-radius: 8px;
        padding: 16px;
        font-size: 14px;
        line-height: 1.7;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
        margin-top: 10px;
    }
    .brand-alert {
        background-color: #FFF1F2;
        border: 1px solid #FDA4AF;
        color: #9F1239;
        padding: 12px 16px;
        border-radius: 8px;
        font-weight: 600;
        margin-bottom: 14px;
    }
    .threat-meter {
        font-size: 2.4rem;
        font-weight: 800;
        margin-bottom: 4px;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def load_detector():
    return PhishingDetector()

detector = load_detector()

def record_incident(scan_type: str, target: str, score: int, verdict: str, red_flags: list = None):
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": scan_type,
        "target": target[:80],
        "risk_score": score,
        "verdict": verdict,
        "red_flags": red_flags or []
    }
    st.session_state.audit_history.append(entry)
    return entry

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=64)
    st.title("PhishGuard Enterprise")
    st.caption("AI-Powered Threat Defense Ecosystem v2.1")
    st.markdown("---")
    st.markdown("""
    **Defensive Capabilities:**
    * 🌲 **Lexical URL Classifier:** Random Forest + DGA Entropy
    * 🎯 **Brand Radar:** Homoglyphs & Combosquatting
    * 🧠 **NLP Email Analyzer:** TF-IDF + Social Engineering Signals
    * 📧 **RFC 822 Header Auditor:** SPF / DKIM / Domain Alignment
    * 📷 **Quishing Engine:** QR Code Phishing Defense
    * 📋 **SOC Playbook:** Automated Executive Incident Reports
    * ⚡ **FastAPI Server:** [Swagger Docs (Port 8000)](http://localhost:8000/docs)
    * 🧩 **Chrome Extension:** `browser_extension/`
    * 🐳 **Docker Support:** `docker compose up`
    """)
    st.markdown("---")
    if st.button("🔄 Retrain AI Models"):
        with st.spinner("Retraining URL & Email models..."):
            train_all()
            st.cache_resource.clear()
            detector = load_detector()
            st.success("Models retrained and reloaded successfully!")

# Header
st.markdown('<div class="main-header">🛡️ PhishGuard AI Threat Intelligence Center</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Enterprise defense platform for detecting brand typosquatting, email spoofing, malicious links, and quishing vectors.</div>', unsafe_allow_html=True)

# Tabs
tab_url, tab_email, tab_eml, tab_qr, tab_history, tab_dataset, tab_metrics = st.tabs([
    "🔗 URL & Brand Radar",
    "✉️ Email Inspector (XAI)",
    "📧 Raw .EML Header Auditor",
    "📷 Quishing (QR Phishing)",
    "📋 Threat Audit & Reports",
    "📁 Custom Dataset Importer",
    "📊 Model Performance"
])

# ----------------- TAB 1: URL & BRAND RADAR -----------------
with tab_url:
    st.subheader("Analyze Suspicious URLs & Brand Impersonation")
    st.write("Detects domain structure anomalies, Shannon entropy, homoglyphs, and brand typosquatting targeting 50+ monitored institutions.")

    col_btn1, col_btn2, col_btn3, col_btn4 = st.columns(4)
    sample_url = ""
    with col_btn1:
        if st.button("Example 1: Safe Microsoft Docs"):
            sample_url = "https://learn.microsoft.com/en-us/azure/security"
    with col_btn2:
        if st.button("Example 2: PayPal Typosquat (paypa1)"):
            sample_url = "http://paypa1-security-verification.xyz/login.php"
    with col_btn3:
        if st.button("Example 3: IP-Address Host"):
            sample_url = "http://192.168.1.105:8080/chase/auth"
    with col_btn4:
        if st.button("Example 4: Subdomain Brand Trap"):
            sample_url = "http://apple.com.secure.account.verify.auth-portal-992.top/sign-in"

    url_input = st.text_input("Enter URL to scan:", value=sample_url, placeholder="e.g. http://paypal-verify-account.xyz")

    if st.button("🔍 Scan URL", type="primary", key="btn_scan_url") or url_input:
        if not url_input.strip():
            st.info("Please enter a URL to scan.")
        else:
            with st.spinner("Extracting lexical signals and querying brand intelligence..."):
                res = detector.predict_url(url_input)
                record_incident("URL", url_input, res["risk_score"], res["verdict"], res.get("red_flags", []))

            score = res["risk_score"]
            c1, c2 = st.columns([1, 2])

            with c1:
                st.metric(label="Threat Risk Score", value=f"{score}/100")
                if res["severity"] == "danger":
                    st.markdown(f'<span class="badge-danger">🚨 {res["verdict"]}</span>', unsafe_allow_html=True)
                elif res["severity"] == "warning":
                    st.markdown(f'<span class="badge-warning">⚠️ {res["verdict"]}</span>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<span class="badge-success">✅ {res["verdict"]}</span>', unsafe_allow_html=True)

                st.write("")
                st.progress(score / 100)
                st.caption(f"Estimated Malicious Probability: **{res['probability']*100:.1f}%**")

                # One-click Executive Report Download
                report_html = generate_executive_html_report({
                    "target": url_input,
                    "type": "URL & Brand Spoofing Scan",
                    "risk_score": score,
                    "verdict": res["verdict"],
                    "red_flags": res.get("red_flags", [])
                })
                st.download_button(
                    "📥 Download Executive Incident Report",
                    data=report_html,
                    file_name=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                    mime="text/html",
                    key="dl_report_url"
                )

            with c2:
                brand_info = res.get("brand_intelligence", {})
                if brand_info.get("impersonated"):
                    st.markdown(f'''
                    <div class="brand-alert">
                        🎯 <strong>TARGETED BRAND SPOOFING DETECTED</strong><br>
                        • <strong>Target Brand:</strong> {brand_info.get("target_brand")}<br>
                        • <strong>Attack Pattern:</strong> {brand_info.get("attack_type")}<br>
                        • <strong>Details:</strong> {brand_info.get("description")}
                    </div>
                    ''', unsafe_allow_html=True)

                st.markdown("##### Threat Indicators & Red Flags")
                if res["red_flags"]:
                    for rf in res["red_flags"]:
                        st.markdown(f"- 🚩 **{rf}**")
                else:
                    st.markdown("🟢 *No high-risk structural heuristics or blacklisted patterns triggered.*")

            st.markdown("---")
            st.markdown("##### Extracted Lexical & Domain Signals")
            feat = res["features"]
            f_col1, f_col2, f_col3, f_col4 = st.columns(4)
            f_col1.metric("Domain Entropy", f"{feat['domain_entropy']:.2f}")
            f_col2.metric("Subdomain Depth", int(feat['subdomain_count']))
            f_col3.metric("SSL/HTTPS", "Yes" if feat['has_https'] == 1 else "No (Insecure)")
            f_col4.metric("Direct IP Host?", "Yes (Suspicious)" if feat['has_ip'] == 1 else "No")

# ----------------- TAB 2: EMAIL INSPECTOR (XAI) -----------------
with tab_email:
    st.subheader("Social Engineering & Explainable AI (XAI) Email Inspector")
    st.write("Identifies psychological manipulation (urgency, panic, fear, greed) with visual Explainable AI highlighting.")

    col_e1, col_e2 = st.columns(2)
    sample_subj = ""
    sample_body = ""

    with col_e1:
        if st.button("Example: Clean Project Standup"):
            sample_subj = "Weekly Team Sync Agenda"
            sample_body = "Hi team,\nHere is the agenda for tomorrow's sprint sync:\n1. Roadmap review\n2. Q3 bug fixes\n3. Database migration schedule.\nPlease review the docs attached on Confluence beforehand. See you all at 10 AM."
    with col_e2:
        if st.button("Example: Phishing Suspension Lure"):
            sample_subj = "URGENT: Immediate Account Suspension Notice"
            sample_body = "Dear Customer,\nWe detected unauthorized login attempts from an unknown device. Your bank access will be permanently terminated within 24 hours unless you verify your password and identity immediately: http://paypa1-security-verification.xyz/login.php"

    subject_input = st.text_input("Email Subject:", value=sample_subj, placeholder="e.g. Urgent: Update your billing credentials")
    body_input = st.text_area("Email Body:", value=sample_body, height=160, placeholder="Paste email content here...")

    if st.button("🔬 Analyze Email Content", type="primary", key="btn_scan_email") or (subject_input and body_input):
        if not body_input.strip() and not subject_input.strip():
            st.info("Please provide email subject or body.")
        else:
            with st.spinner("Analyzing linguistic patterns and behavioral cues..."):
                res = detector.predict_email(subject_input, body_input)
                record_incident("Email", subject_input or body_input[:40], res["risk_score"], res["verdict"], res.get("red_flags", []))

            score = res["risk_score"]
            c1, c2 = st.columns([1, 2])

            with c1:
                st.metric(label="Email Threat Score", value=f"{score}/100")
                if res["severity"] == "danger":
                    st.markdown(f'<span class="badge-danger">🚨 {res["verdict"]}</span>', unsafe_allow_html=True)
                elif res["severity"] == "warning":
                    st.markdown(f'<span class="badge-warning">⚠️ {res["verdict"]}</span>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<span class="badge-success">✅ {res["verdict"]}</span>', unsafe_allow_html=True)

                st.write("")
                st.progress(score / 100)
                st.caption(f"Confidence: **{res['probability']*100:.1f}%**")

                report_html = generate_executive_html_report({
                    "target": f"Subject: {subject_input}",
                    "type": "Email Social Engineering Audit",
                    "risk_score": score,
                    "verdict": res["verdict"],
                    "red_flags": res.get("red_flags", [])
                })
                st.download_button(
                    "📥 Download Executive Incident Report",
                    data=report_html,
                    file_name=f"email_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                    mime="text/html",
                    key="dl_report_email"
                )

            with c2:
                st.markdown("##### Detected Psychological & Linguistic Triggers")
                if res["red_flags"]:
                    for rf in res["red_flags"]:
                        st.markdown(f"- 🚩 **{rf}**")
                else:
                    st.markdown("🟢 *Natural business communication tone. No high-pressure triggers identified.*")

            st.markdown("---")
            st.markdown("##### 🔍 Explainable AI (XAI) Visual Text Breakdown")
            st.markdown("""
            *Color Key:* 
            <span style="background:#FEE2E2; color:#991B1B; padding:2px 6px; border-radius:4px; font-weight:bold;">Red: Credential Lure</span> | 
            <span style="background:#FFEDD5; color:#9A3412; padding:2px 6px; border-radius:4px; font-weight:bold;">Orange: Urgency Trigger</span> | 
            <span style="background:#FEF9C3; color:#854D0E; padding:2px 6px; border-radius:4px; font-weight:bold;">Yellow: Financial Scam</span> | 
            <span style="background:#F3E8FF; color:#6B21A8; padding:2px 6px; border-radius:4px; font-weight:bold;">Purple: Generic Salutation</span> | 
            <span style="background:#E0F2FE; color:#0369A1; padding:2px 6px; border-radius:4px; font-weight:bold;">Blue: Web Link</span>
            """, unsafe_allow_html=True)

            highlighted_html = highlight_email_threat_cues(f"Subject: {subject_input}\n\n{body_input}")
            st.markdown(f'<div class="xai-box">{highlighted_html}</div>', unsafe_allow_html=True)

# ----------------- TAB 3: RAW .EML HEADER AUDITOR -----------------
with tab_eml:
    st.subheader("Raw RFC 822 (.eml) File & Header Spoof Auditor")
    st.write("Upload exported email files (.eml) to audit SPF/DKIM authentication, sender domain spoofing, and dangerous attachments.")

    sample_eml_col1, sample_eml_col2 = st.columns(2)
    with sample_eml_col1:
        if st.button("🧪 Generate & Test Sample Spoofed .EML"):
            sample_eml_bytes = b"""From: PayPal Security <security@paypal-update-alert.xyz>
To: target-user@example.com
Subject: URGENT: Your PayPal Account Has Been Suspended
Date: Sun, 18 Oct 2026 07:45:00 +0000
Reply-To: credential-collector@attacker-server.net
Return-Path: bounce@attacker-server.net
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/plain; charset="utf-8"

Dear Customer,
We detected unauthorized login attempts from Moscow, Russia.
Your account has been restricted. You must verify your password and banking details within 24 hours:
http://paypa1-security-verification.xyz/login.php

Failure to do so will result in immediate termination.
PayPal Security Team.
"""
            st.session_state.test_eml_bytes = sample_eml_bytes
            st.success("Sample spoofed .eml generated! Click 'Audit .EML File' below.")

    uploaded_eml = st.file_uploader("Upload .eml file from Outlook / Apple Mail / Thunderbird:", type=["eml"])
    eml_to_scan = uploaded_eml.read() if uploaded_eml is not None else st.session_state.get("test_eml_bytes")

    if eml_to_scan and st.button("🛡️ Audit .EML File", type="primary"):
        with st.spinner("Parsing RFC 822 headers, verifying domain alignment, and inspecting payloads..."):
            eml_audit = detector.scan_eml(eml_to_scan)
            record_incident(".EML", eml_audit["headers"]["subject"] or "EML File", eml_audit["composite_risk_score"], eml_audit["composite_verdict"], eml_audit.get("spoofing_flags", []))

        score = eml_audit["composite_risk_score"]
        col_eml1, col_eml2 = st.columns([1, 2])

        with col_eml1:
            st.metric("Total .EML Threat Score", f"{score}/100")
            if eml_audit["composite_severity"] == "danger":
                st.markdown(f'<span class="badge-danger">🚨 {eml_audit["composite_verdict"]}</span>', unsafe_allow_html=True)
            elif eml_audit["composite_severity"] == "warning":
                st.markdown(f'<span class="badge-warning">⚠️ {eml_audit["composite_verdict"]}</span>', unsafe_allow_html=True)
            else:
                st.markdown(f'<span class="badge-success">✅ {eml_audit["composite_verdict"]}</span>', unsafe_allow_html=True)
            st.write("")
            st.progress(score / 100)

            report_html = generate_executive_html_report({
                "target": eml_audit["headers"]["subject"],
                "type": ".EML Raw Header & Attachment Audit",
                "risk_score": score,
                "verdict": eml_audit["composite_verdict"],
                "red_flags": eml_audit.get("spoofing_flags", [])
            })
            st.download_button(
                "📥 Download Executive Incident Report",
                data=report_html,
                file_name=f"eml_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                mime="text/html",
                key="dl_report_eml"
            )

        with col_eml2:
            st.markdown("##### Header Alignment & Authentication Status")
            auth = eml_audit["auth_security"]
            a1, a2, a3 = st.columns(3)
            a1.metric("SPF Pass?", "Pass" if auth["spf_pass"] else "Fail / None")
            a2.metric("DKIM Pass?", "Pass" if auth["dkim_pass"] else "Fail / None")
            a3.metric("DMARC Pass?", "Pass" if auth["dmarc_pass"] else "Fail / None")

            if eml_audit["spoofing_flags"]:
                st.write("**Header Spoofing Violations:**")
                for sf in eml_audit["spoofing_flags"]:
                    st.markdown(f"- ⚠️ **{sf}**")
            else:
                st.markdown("🟢 *No domain spoofing or SPF/DKIM mismatches detected.*")

        st.markdown("---")
        h = eml_audit["headers"]
        st.markdown(f"**From:** `{h['from']}` | **Reply-To:** `{h['reply_to'] or 'Same'}` | **Subject:** `{h['subject']}`")

        if eml_audit["attachments"]:
            st.markdown("##### Attachments Inspection:")
            for att in eml_audit["attachments"]:
                badge = "🚨 DANGEROUS EXECUTABLE" if att["is_dangerous"] else ("⚠️ COMPRESSED ARCHIVE" if att["is_archive"] else "📄 Normal File")
                st.write(f"- `{att['filename']}` ({att['size_bytes']} bytes) — **{badge}**")

        st.markdown("##### Explainable Text Analysis:")
        highlighted = highlight_email_threat_cues(eml_audit.get("body_text", ""))
        st.markdown(f'<div class="xai-box">{highlighted}</div>', unsafe_allow_html=True)

# ----------------- TAB 4: QUISHING (QR PHISHING) -----------------
with tab_qr:
    st.subheader("📷 Quishing (QR Code Phishing) Defense Scanner")
    st.write("Detects QR codes embedded in email attachments, MFA-reset prompts, and invoices designed to evade email perimeter gateways.")

    uploaded_qr = st.file_uploader("Upload Image Containing QR Code (PNG, JPG, WEBP):", type=["png", "jpg", "jpeg", "webp"])

    sample_qr_url = st.text_input("Or simulate testing a QR payload directly:", value="http://paypa1-security-verification.xyz/login.php")

    if uploaded_qr is not None:
        if st.button("🔍 Scan Uploaded QR Image", type="primary"):
            with st.spinner("Extracting QR barcode and evaluating destination threat..."):
                qr_res = analyze_quishing_threat(uploaded_qr.read(), detector)
                record_incident("Quishing", qr_res.get("extracted_url") or "QR Image", qr_res["risk_score"], qr_res["verdict"], qr_res.get("flags", []))

            st.write("---")
            q_col1, q_col2 = st.columns([1, 2])
            with q_col1:
                st.metric("Quishing Risk Score", f"{qr_res['risk_score']}/100")
                if qr_res.get("severity") == "danger":
                    st.markdown(f'<span class="badge-danger">🚨 {qr_res["verdict"]}</span>', unsafe_allow_html=True)
                elif qr_res.get("severity") == "warning":
                    st.markdown(f'<span class="badge-warning">⚠️ {qr_res["verdict"]}</span>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<span class="badge-success">✅ {qr_res["verdict"]}</span>', unsafe_allow_html=True)

            with q_col2:
                st.write(f"**Decoded URL Payload:** `{qr_res.get('extracted_url') or 'None'}`")
                for f in qr_res.get("flags", []):
                    st.markdown(f"- 🚩 {f}")

    elif sample_qr_url:
        if st.button("🧪 Simulate Quishing Vector Analysis", type="primary"):
            u_analysis = detector.predict_url(sample_qr_url)
            quish_score = min(100, u_analysis["risk_score"] + 15)
            q_verdict = "MALICIOUS QUISHING (High Risk QR Phishing)" if quish_score >= 70 else "SUSPICIOUS QR CODE"
            record_incident("Quishing Simulation", sample_qr_url, quish_score, q_verdict, u_analysis.get("red_flags", []))

            st.write("---")
            q_col1, q_col2 = st.columns([1, 2])
            with q_col1:
                st.metric("Simulated Quishing Score", f"{quish_score}/100")
                badge_class = "badge-danger" if quish_score >= 70 else "badge-warning"
                st.markdown(f'<span class="{badge_class}">🚨 {q_verdict}</span>', unsafe_allow_html=True)
            with q_col2:
                st.write(f"**Target URL Decoded from Simulated QR:** `{sample_qr_url}`")
                st.markdown("- 🚩 **Image contains an embedded QR code (Quishing Vector: Designed to bypass text email filters)**")
                for f in u_analysis.get("red_flags", []):
                    st.markdown(f"- 🚩 {f}")

# ----------------- TAB 5: THREAT AUDIT HISTORY & REPORTS -----------------
with tab_history:
    st.subheader("📋 Session Threat Audit History & SOC Playbooks")
    st.write("Track all scans performed during this analyst session. Export reports for Security Operations (SOC) escalation.")

    if st.session_state.audit_history:
        df_hist = pd.DataFrame(st.session_state.audit_history)
        st.dataframe(df_hist[["timestamp", "type", "target", "risk_score", "verdict"]], use_container_width=True)

        col_dl1, col_dl2 = st.columns(2)
        with col_dl1:
            csv_data = df_hist.to_csv(index=False).encode('utf-8')
            st.download_button(
                "📥 Export Incident Log (CSV)",
                data=csv_data,
                file_name="phishguard_incident_log.csv",
                mime="text/csv"
            )
        with col_dl2:
            json_data = json.dumps(st.session_state.audit_history, indent=2)
            st.download_button(
                "📥 Export SOC Incident Report (JSON)",
                data=json_data,
                file_name="phishguard_threat_report.json",
                mime="application/json"
            )
    else:
        st.info("No scans recorded yet in this session. Scan URLs, Emails, or QR codes to populate the incident log.")

# ----------------- TAB 6: CUSTOM DATASET IMPORTER -----------------
with tab_dataset:
    st.subheader("Connect Custom Dataset & Retrain")
    st.write("Upload custom CSV files from Kaggle, PhishTank, or your organization's threat feed to retrain the models.")

    dataset_type = st.radio("Select Target Classifier to Retrain:", ["URL Phishing Dataset", "Email Phishing Dataset"], horizontal=True)

    if dataset_type == "URL Phishing Dataset":
        st.markdown("**Required Columns:** `url` (text string) and `label` (0 for legitimate, 1 for phishing)")
        uploaded_file = st.file_uploader("Upload URL CSV file:", type=["csv"], key="uploader_url")
        if uploaded_file is not None:
            df_up = pd.read_csv(uploaded_file)
            st.write(f"Preview (Total rows: {len(df_up)}):")
            st.dataframe(df_up.head(5), use_container_width=True)

            if "url" in df_up.columns and "label" in df_up.columns:
                if st.button("🚀 Train URL Model on Uploaded CSV", type="primary"):
                    save_path = os.path.join(os.path.dirname(__file__), "data", "urls_custom.csv")
                    df_up.to_csv(save_path, index=False)
                    model_path = os.path.join(os.path.dirname(__file__), "models", "url_classifier.joblib")
                    with st.spinner("Training Random Forest model on uploaded dataset..."):
                        metrics = train_url_model(save_path, model_path)
                    st.cache_resource.clear()
                    detector = load_detector()
                    st.success(f"Successfully retrained! Accuracy: {metrics['accuracy']*100:.2f}%, F1: {metrics['f1']*100:.2f}%")
            else:
                st.error("Uploaded CSV must contain columns 'url' and 'label'")

    else:
        st.markdown("**Required Columns:** `subject` (string), `body` (string), and `label` (0 for legitimate, 1 for phishing)")
        uploaded_file = st.file_uploader("Upload Email CSV file:", type=["csv"], key="uploader_email")
        if uploaded_file is not None:
            df_up = pd.read_csv(uploaded_file)
            st.write(f"Preview (Total rows: {len(df_up)}):")
            st.dataframe(df_up.head(5), use_container_width=True)

            if "subject" in df_up.columns and "body" in df_up.columns and "label" in df_up.columns:
                if st.button("🚀 Train Email Model on Uploaded CSV", type="primary"):
                    save_path = os.path.join(os.path.dirname(__file__), "data", "emails_custom.csv")
                    df_up.to_csv(save_path, index=False)
                    model_path = os.path.join(os.path.dirname(__file__), "models", "email_classifier.joblib")
                    with st.spinner("Training NLP + Metadata model on uploaded dataset..."):
                        metrics = train_email_model(save_path, model_path)
                    st.cache_resource.clear()
                    detector = load_detector()
                    st.success(f"Successfully retrained! Accuracy: {metrics['accuracy']*100:.2f}%, F1: {metrics['f1']*100:.2f}%")
            else:
                st.error("Uploaded CSV must contain columns 'subject', 'body', and 'label'")

# ----------------- TAB 7: MODEL PERFORMANCE -----------------
with tab_metrics:
    st.subheader("Model Evaluation & Training Metrics")
    st.write("Trained classifiers performance evaluated on independent holdout test partitions.")

    m_col1, m_col2 = st.columns(2)

    url_meta = detector.url_bundle.get("metrics", {}) if detector.url_bundle else {}
    email_meta = detector.email_bundle.get("metrics", {}) if detector.email_bundle else {}

    with m_col1:
        st.markdown("#### 🌲 URL Classifier (Random Forest)")
        st.write(f"**Total Samples:** {url_meta.get('total_samples', 'N/A')} | **Test Partition:** {url_meta.get('test_samples', 'N/A')}")
        k1, k2 = st.columns(2)
        k1.metric("Accuracy", f"{url_meta.get('accuracy', 0)*100:.2f}%")
        k1.metric("Precision", f"{url_meta.get('precision', 0)*100:.2f}%")
        k2.metric("Recall", f"{url_meta.get('recall', 0)*100:.2f}%")
        k2.metric("F1-Score", f"{url_meta.get('f1', 0)*100:.2f}%")

        if detector.url_bundle and "top_features" in detector.url_bundle:
            st.markdown("##### Top Predictive Feature Importances:")
            df_feat = pd.DataFrame(detector.url_bundle["top_features"])
            st.dataframe(df_feat, use_container_width=True)

    with m_col2:
        st.markdown("#### 🧠 Email Classifier (NLP + Metadata)")
        st.write(f"**Total Samples:** {email_meta.get('total_samples', 'N/A')} | **Test Partition:** {email_meta.get('test_samples', 'N/A')}")
        e1, e2 = st.columns(2)
        e1.metric("Accuracy", f"{email_meta.get('accuracy', 0)*100:.2f}%")
        e1.metric("Precision", f"{email_meta.get('precision', 0)*100:.2f}%")
        e2.metric("Recall", f"{email_meta.get('recall', 0)*100:.2f}%")
        e2.metric("F1-Score", f"{email_meta.get('f1', 0)*100:.2f}%")

        st.markdown("##### Confusion Matrix (Holdout Set):")
        cm = email_meta.get("confusion_matrix", [[0, 0], [0, 0]])
        cm_df = pd.DataFrame(cm, columns=["Pred: Legit", "Pred: Phish"], index=["Actual: Legit", "Actual: Phish"])
        st.dataframe(cm_df, use_container_width=True)
