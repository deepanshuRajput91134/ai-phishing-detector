import os
import sys
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

# Ensure src is in python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from predictor import PhishingDetector
from xai_highlighter import highlight_email_threat_cues

app = FastAPI(
    title="PhishGuard Enterprise AI Threat Intelligence API",
    description="Dual-engine AI API for real-time URL Typosquatting, Email NLP, RFC 822 .eml Header Audits, and XAI Explanations",
    version="2.0.0"
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


class EmailScanRequest(BaseModel):
    subject: str = Field(..., example="URGENT: Immediate Account Suspension")
    body: str = Field(..., example="Dear Customer, verify your credentials immediately within 24 hours: http://192.168.1.50/login.php")


@app.get("/")
def root():
    return {
        "service": "PhishGuard Enterprise AI Threat Intelligence Engine",
        "status": "online",
        "version": "2.0.0",
        "ready": detector.is_ready(),
        "documentation": "/docs"
    }


@app.post("/api/scan-url")
def scan_url(req: URLScanRequest):
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    try:
        result = detector.predict_url(req.url.strip())
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
        result = detector.scan_full_email(req.subject, req.body)
        result["xai_highlighted_html"] = highlight_email_threat_cues(f"{req.subject}\n\n{req.body}")
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan-eml")
async def scan_eml_file(file: UploadFile = File(...)):
    """Uploads and analyzes raw RFC 822 (.eml) email file with header spoof & attachment inspection."""
    try:
        content = await file.read()
        result = detector.scan_eml(content)
        result["xai_highlighted_html"] = highlight_email_threat_cues(result.get("body_text", ""))
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse .eml file: {str(e)}")


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
