import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from scipy.sparse import hstack

from features import (
    extract_url_features,
    extract_url_red_flags,
    extract_email_metadata_features,
    extract_email_red_flags,
    extract_urls_from_text
)
from domain_intel import analyze_brand_impersonation
from eml_parser import parse_eml_file


class PhishingDetector:
    """
    Enterprise-Grade Unified Inference Engine for Phishing Detection.
    Features:
    - URL Structural Tree Classifier + Brand Typosquatting & Punycode Intelligence
    - NLP Social Engineering Linguistic Engine
    - End-to-end Multi-layer Correlation
    - RFC 822 .eml Raw Email & Header Spoof Analyzer
    """
    def __init__(self, models_dir: Optional[str] = None):
        if models_dir is None:
            models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
        self.models_dir = models_dir
        self.url_bundle = None
        self.email_bundle = None
        self._load_models()

    def _load_models(self):
        url_path = os.path.join(self.models_dir, "url_classifier.joblib")
        email_path = os.path.join(self.models_dir, "email_classifier.joblib")

        if os.path.exists(url_path):
            self.url_bundle = joblib.load(url_path)
        if os.path.exists(email_path):
            self.email_bundle = joblib.load(email_path)

    def is_ready(self) -> bool:
        return self.url_bundle is not None and self.email_bundle is not None

    def predict_url(self, url: str) -> Dict[str, Any]:
        """Analyzes a given URL with ML features + Brand Typosquatting Threat Intel."""
        if not self.url_bundle:
            self._load_models()
        if not self.url_bundle:
            raise RuntimeError("URL classifier model is not trained yet. Run train.py first.")

        features_dict = extract_url_features(url)
        df_features = pd.DataFrame([features_dict])
        
        feature_names = self.url_bundle["feature_names"]
        X = df_features[feature_names].values

        model = self.url_bundle["model"]
        prob_phish = float(model.predict_proba(X)[0][1])

        # Brand Impersonation Threat Intel Check
        parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
        host = (parsed.hostname or "").lower()
        brand_intel = analyze_brand_impersonation(host)

        # Integrate threat intel bonus
        red_flags = extract_url_red_flags(url, features_dict)
        if brand_intel["impersonated"]:
            prob_phish = min(1.0, prob_phish + (brand_intel["risk_bonus"] / 100.0))
            red_flags.insert(0, f"BRAND TARGETING: {brand_intel['description']}")

        risk_score = int(round(prob_phish * 100))
        prediction = int(risk_score >= 50)

        if risk_score >= 70:
            verdict = "PHISHING (High Risk)"
            severity = "danger"
        elif risk_score >= 40:
            verdict = "SUSPICIOUS (Medium Risk)"
            severity = "warning"
        else:
            verdict = "LEGITIMATE (Low Risk)"
            severity = "success"

        return {
            "target": url,
            "is_phishing": bool(prediction),
            "probability": prob_phish,
            "risk_score": risk_score,
            "verdict": verdict,
            "severity": severity,
            "red_flags": red_flags,
            "brand_intelligence": brand_intel,
            "features": features_dict,
        }

    def predict_email(self, subject: str, body: str) -> Dict[str, Any]:
        """Analyzes email subject and body for social engineering lures."""
        if not self.email_bundle:
            self._load_models()
        if not self.email_bundle:
            raise RuntimeError("Email classifier model is not trained yet. Run train.py first.")

        combined_text = f"{subject} {body}"
        meta_dict = extract_email_metadata_features(subject, body)
        meta_cols = self.email_bundle["meta_cols"]
        
        meta_df = pd.DataFrame([meta_dict])[meta_cols]
        meta_scaled = self.email_bundle["scaler"].transform(meta_df.values)

        tfidf_vec = self.email_bundle["vectorizer"].transform([combined_text])
        X_combined = hstack([tfidf_vec, meta_scaled])

        model = self.email_bundle["model"]
        prob_phish = float(model.predict_proba(X_combined)[0][1])
        prediction = int(prob_phish >= 0.5)

        risk_score = int(round(prob_phish * 100))
        if risk_score >= 70:
            verdict = "PHISHING (High Risk)"
            severity = "danger"
        elif risk_score >= 40:
            verdict = "SUSPICIOUS (Medium Risk)"
            severity = "warning"
        else:
            verdict = "LEGITIMATE (Low Risk)"
            severity = "success"

        red_flags = extract_email_red_flags(subject, body, meta_dict)

        return {
            "subject": subject,
            "body_snippet": body[:200] + ("..." if len(body) > 200 else ""),
            "is_phishing": bool(prediction),
            "probability": prob_phish,
            "risk_score": risk_score,
            "verdict": verdict,
            "severity": severity,
            "red_flags": red_flags,
            "metadata_features": meta_dict
        }

    def scan_full_email(self, subject: str, body: str) -> Dict[str, Any]:
        """End-to-End multi-layer correlation between text cues & embedded hyperlinks."""
        email_result = self.predict_email(subject, body)
        
        extracted_urls = extract_urls_from_text(body)
        url_results = []
        for u in extracted_urls:
            try:
                url_results.append(self.predict_url(u))
            except Exception as e:
                url_results.append({
                    "target": u,
                    "error": str(e),
                    "risk_score": 50,
                    "verdict": "ERROR"
                })

        email_risk = email_result["risk_score"]
        if url_results:
            max_url_risk = max(r.get("risk_score", 0) for r in url_results)
            composite_risk = int(round(0.4 * email_risk + 0.6 * max_url_risk))
        else:
            composite_risk = email_risk

        if composite_risk >= 70:
            composite_verdict = "MALICIOUS / PHISHING ATTACK DETECTED"
            composite_severity = "danger"
        elif composite_risk >= 40:
            composite_verdict = "SUSPICIOUS EMAIL / REVIEW CAREFULLY"
            composite_severity = "warning"
        else:
            composite_verdict = "CLEAN / BENIGN EMAIL"
            composite_severity = "success"

        return {
            "email_analysis": email_result,
            "extracted_urls": extracted_urls,
            "url_analysis": url_results,
            "composite_risk_score": composite_risk,
            "composite_verdict": composite_verdict,
            "composite_severity": composite_severity
        }

    def scan_eml(self, eml_bytes: bytes) -> Dict[str, Any]:
        """
        Deep security audit of raw .eml RFC 822 file:
        - Domain spoofing (From vs Reply-To vs Return-Path)
        - SPF, DKIM, DMARC validation
        - Dangerous attachments detection
        - Embedded HTML links & Text body AI scan
        """
        parsed_eml = parse_eml_file(eml_bytes)
        subj = parsed_eml["headers"]["subject"]
        body = parsed_eml["body_text"]

        # Run composite scan on the extracted text & links
        composite_scan = self.scan_full_email(subj, body)

        # Also add any links extracted from HTML <a> tags that weren't in plain text
        existing_urls = set(composite_scan["extracted_urls"])
        for h_link in parsed_eml["html_links"]:
            if h_link not in existing_urls:
                try:
                    u_eval = self.predict_url(h_link)
                    composite_scan["url_analysis"].append(u_eval)
                    composite_scan["extracted_urls"].append(h_link)
                except Exception:
                    pass

        # Factor in email spoofing and attachment penalties
        spoof_penalty = len(parsed_eml["spoofing_flags"]) * 20
        has_dangerous_att = any(a["is_dangerous"] for a in parsed_eml["attachments"])
        if has_dangerous_att:
            spoof_penalty += 35

        final_risk = min(100, composite_scan["composite_risk_score"] + spoof_penalty)
        if final_risk >= 70:
            final_verdict = "HIGH-RISK MALICIOUS EMAIL (.EML)"
            final_severity = "danger"
        elif final_risk >= 40:
            final_verdict = "SUSPICIOUS EMAIL (.EML)"
            final_severity = "warning"
        else:
            final_verdict = "CLEAN EMAIL (.EML)"
            final_severity = "success"

        return {
            "headers": parsed_eml["headers"],
            "auth_security": parsed_eml["auth_security"],
            "spoofing_flags": parsed_eml["spoofing_flags"],
            "attachments": parsed_eml["attachments"],
            "composite_risk_score": final_risk,
            "composite_verdict": final_verdict,
            "composite_severity": final_severity,
            "body_text": body,
            "url_analysis": composite_scan["url_analysis"],
            "email_analysis": composite_scan["email_analysis"]
        }
