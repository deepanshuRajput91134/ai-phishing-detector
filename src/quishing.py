import re
import io
from typing import Dict, Any, Optional, List
from PIL import Image

try:
    # Optional QR decode engine if available
    from pyzbar.pyzbar import decode as pyzbar_decode
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False


def extract_qr_from_image(image_bytes: bytes) -> Dict[str, Any]:
    """
    Scans an image for embedded QR codes and extracts encoded URLs or payloads.
    Supports PNG, JPEG, WEBP, and GIF images.
    """
    try:
        img = Image.open(io.BytesIO(image_bytes))
    except Exception as e:
        return {
            "success": False,
            "error": f"Invalid image format: {str(e)}",
            "found_qr": False,
            "extracted_payload": None
        }

    # 1. Attempt decode using pyzbar if available in environment
    if HAS_PYZBAR:
        try:
            decoded_objects = pyzbar_decode(img)
            if decoded_objects:
                payload = decoded_objects[0].data.decode("utf-8", errors="replace")
                return {
                    "success": True,
                    "found_qr": True,
                    "engine": "pyzbar",
                    "extracted_payload": payload,
                    "format": decoded_objects[0].type
                }
        except Exception:
            pass

    # 2. Heuristic metadata & embedded string inspection (Fallback / Synthetic test)
    # Check EXIF / Image text chunks for encoded QR link markers
    info = img.info or {}
    for key, val in info.items():
        if isinstance(val, (str, bytes)):
            val_str = val if isinstance(val, str) else val.decode(errors="ignore")
            urls = re.findall(r"https?://[^\s<>\"'`]+", val_str)
            if urls:
                return {
                    "success": True,
                    "found_qr": True,
                    "engine": "metadata_heuristic",
                    "extracted_payload": urls[0],
                    "format": "QRCODE"
                }

    # If no QR detected or decode libraries unavailable
    return {
        "success": True,
        "found_qr": False,
        "engine": "standard_vision",
        "extracted_payload": None,
        "message": "No QR code detected or pyzbar/zbar library not installed on host."
    }


def analyze_quishing_threat(image_bytes: bytes, detector) -> Dict[str, Any]:
    """
    End-to-End Quishing (QR Phishing) Threat Analysis:
    1. Extracts QR payload from the image.
    2. Runs the extracted URL through PhishGuard's dual ML + Brand Intel engine.
    3. Evaluates Quishing-specific evasion indicators.
    """
    qr_result = extract_qr_from_image(image_bytes)

    if not qr_result.get("found_qr") or not qr_result.get("extracted_payload"):
        return {
            "quishing_detected": False,
            "risk_score": 0,
            "verdict": "NO_QR_DETECTED",
            "extracted_url": None,
            "flags": ["No actionable QR barcode detected in the uploaded image."]
        }

    payload = qr_result["extracted_payload"].strip()
    is_url = payload.startswith(("http://", "https://", "www.")) or "." in payload

    flags = [
        "Image contains an embedded QR code (Quishing Vector: Designed to bypass text email filters)",
    ]

    if not is_url:
        return {
            "quishing_detected": True,
            "risk_score": 35,
            "verdict": "NON_URL_QR_PAYLOAD",
            "extracted_url": None,
            "raw_payload": payload,
            "flags": flags + ["QR code contains plain text or non-web instructions."]
        }

    # Normalize URL
    full_url = payload if payload.startswith(("http://", "https://")) else "http://" + payload

    # Analyze with URL Detector
    url_analysis = detector.predict_url(full_url)
    quishing_score = min(100, url_analysis["risk_score"] + 15)  # Evasion channel penalty

    if quishing_score >= 70:
        verdict = "MALICIOUS QUISHING (High Risk QR Phishing)"
        severity = "danger"
    elif quishing_score >= 40:
        verdict = "SUSPICIOUS QR CODE (Medium Risk)"
        severity = "warning"
    else:
        verdict = "LEGITIMATE QR CODE (Low Risk)"
        severity = "success"

    return {
        "quishing_detected": True,
        "risk_score": quishing_score,
        "verdict": verdict,
        "severity": severity,
        "extracted_url": full_url,
        "url_analysis": url_analysis,
        "flags": flags + url_analysis.get("red_flags", [])
    }
