import os
import sys
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

# Ensure src is in python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from predictor import PhishingDetector
from xai_highlighter import highlight_email_threat_cues
from quishing import analyze_quishing_threat
from report_generator import generate_executive_html_report
from live_threat_intel import fetch_domain_whois_rdap, audit_ssl_certificate, query_virustotal_reputation

app = FastAPI(
    title="PhishGuard Enterprise AI Threat Intelligence API",
    description="Dual-engine AI API for real-time URL Typosquatting, Live WHOIS Domain Age, SSL/TLS Audits, Quishing Scanner, and Executive Reporting",
    version="2.2.0"
)

# Enable CORS for browser extensions and external integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize detector
detector = PhishingDetector()


class URLScanRequest(BaseModel):
    url: str = Field(..., example="http://paypal-security-alert.xyz/verify_credentials.html")
    enable_live_intel: bool = Field(default=False, description="Query live WHOIS RDAP domain age & SSL certificate posture")
    vt_api_key: Optional[str] = Field(default=None, description="Optional VirusTotal v3 API key")


class EmailScanRequest(BaseModel):
    subject: str = Field(..., example="URGENT: Immediate Account Suspension")
    body: str = Field(..., example="Dear Customer, verify your credentials immediately within 24 hours: http://192.168.1.50/login.php")
    enable_live_intel: bool = Field(default=False)


class ReportRequest(BaseModel):
    incident_id: Optional[str] = None
    target: str = Field(..., example="http://paypa1-security.xyz")
    type: str = Field(..., example="URL Threat Scan")
    risk_score: int = Field(..., example=95)
    verdict: str = Field(..., example="PHISHING (High Risk)")
    red_flags: list = Field(default_factory=list)


@app.get("/")
def root():
    return {
        "service": "PhishGuard Enterprise AI Threat Intelligence Engine",
        "status": "online",
        "version": "2.2.0",
        "ready": detector.is_ready(),
        "live_intel_supported": True,
        "documentation": "/docs"
    }


@app.post("/api/scan-url")
def scan_url(req: URLScanRequest):
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    try:
        result = detector.predict_url(req.url.strip(), enable_live_intel=req.enable_live_intel, vt_api_key=req.vt_api_key)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan-email")
def scan_email(req: EmailScanRequest):
    try:
        result = detector.predict_email(req.subject, req.body)
        result["xai_highlighted_html"] = highlight_email_threat_cues(f"{req.subject}\n\n{req.body}")
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/deep-scan")
def deep_scan(req: EmailScanRequest):
    """Correlates email text with all embedded URLs for comprehensive assessment."""
    try:
        result = detector.scan_full_email(req.subject, req.body, enable_live_intel=req.enable_live_intel)
        result["xai_highlighted_html"] = highlight_email_threat_cues(f"{req.subject}\n\n{req.body}")
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan-eml")
async def scan_eml_file(file: UploadFile = File(...), enable_live_intel: bool = False):
    """Uploads and analyzes raw RFC 822 (.eml) email file with header spoof & attachment inspection."""
    try:
        content = await file.read()
        result = detector.scan_eml(content, enable_live_intel=enable_live_intel)
        result["xai_highlighted_html"] = highlight_email_threat_cues(result.get("body_text", ""))
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse .eml file: {str(e)}")


@app.post("/api/scan-qr")
async def scan_qr_file(file: UploadFile = File(...)):
    """Uploads and inspects QR code images for Quishing (QR Phishing) threat vectors."""
    try:
        content = await file.read()
        result = analyze_quishing_threat(content, detector)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process QR image: {str(e)}")


@app.get("/api/threat-intel/domain-age")
def get_domain_age(domain: str):
    """Fetches registration date & domain age in days via ICANN RDAP."""
    if not domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty")
    return fetch_domain_whois_rdap(domain)


@app.get("/api/threat-intel/ssl-audit")
def get_ssl_audit(host: str):
    """Audits SSL/TLS certificate issuer, validity days, and self-signed status."""
    if not host:
        raise HTTPException(status_code=400, detail="Host cannot be empty")
    return audit_ssl_certificate(host)


@app.post("/api/export-report", response_class=HTMLResponse)
def export_report(req: ReportRequest):
    """Generates an executive SOC incident report (HTML) for formal reporting and escalation."""
    try:
        html_report = generate_executive_html_report(req.dict())
        return HTMLResponse(content=html_report, status_code=200)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/metrics")
def get_metrics():
    url_metrics = detector.url_bundle.get("metrics") if detector.url_bundle else None
    email_metrics = detector.email_bundle.get("metrics") if detector.email_bundle else None
    return {
        "url_detector_metrics": url_metrics,
        "email_detector_metrics": email_metrics
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=False)
