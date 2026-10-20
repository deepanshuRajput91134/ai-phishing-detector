import ssl
import socket
import json
import base64
import urllib.request
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse


def extract_base_domain(hostname: str) -> str:
    """Extracts the registrable root domain from a hostname (e.g., auth.secure.paypal.com -> paypal.com)."""
    clean = hostname.lower().strip()
    if clean.startswith("www."):
        clean = clean[4:]
    parts = clean.split(".")
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return clean


def audit_ssl_certificate(hostname: str, port: int = 443, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Connects to the target host and audits its SSL/TLS certificate:
    - Certificate Authority (Issuer)
    - Certificate age & days since issuance (newly minted certs are a high phishing indicator)
    - Expiration timeline
    - Subject Alternative Names (SANs)
    """
    clean_host = hostname.strip().lower()
    if clean_host.startswith(("http://", "https://")):
        clean_host = urlparse(clean_host).hostname or clean_host
    if ":" in clean_host:
        clean_host = clean_host.split(":")[0]

    # Don't check IP addresses for SSL domain match
    if not clean_host or clean_host.replace(".", "").isdigit():
        return {
            "has_ssl": False,
            "error": "Target is a raw IP address or invalid host",
            "issuer": None,
            "flags": ["No TLS certificate: Target uses a raw IP address"]
        }

    flags = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Check cert info even if self-signed/expired

        with socket.create_connection((clean_host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # In CERT_NONE, binary cert can be decoded or is minimal
                    return {
                        "has_ssl": True,
                        "issuer": "Encrypted (Self-signed or unverified)",
                        "is_free_cert": True,
                        "flags": ["TLS connection established, but certificate is self-signed or unverified"]
                    }

                # Extract Issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                issuer_org = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer"

                # Free automated CA check (often abused in mass phishing)
                is_free_ca = any(ca in issuer_org.lower() for ca in ["let's encrypt", "zerossl", "cpanel", "cloudflare"])
                if is_free_ca:
                    flags.append(f"Uses automated/free CA certificate ({issuer_org})")

                # Date parsing
                not_before_str = cert.get("notBefore")
                not_after_str = cert.get("notAfter")
                days_since_issued = None
                days_until_expiry = None

                if not_before_str:
                    try:
                        not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
                        days_since_issued = (datetime.utcnow() - not_before).days
                        if days_since_issued <= 7:
                            flags.append(f"Newly minted SSL certificate: Issued only {days_since_issued} days ago")
                    except Exception:
                        pass

                if not_after_str:
                    try:
                        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        days_until_expiry = (not_after - datetime.utcnow()).days
                        if days_until_expiry < 0:
                            flags.append("Expired SSL Certificate detected")
                    except Exception:
                        pass

                # Subject Alternative Names (SANs)
                sans = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]

                return {
                    "has_ssl": True,
                    "issuer": issuer_org,
                    "is_free_cert": is_free_ca,
                    "days_since_issued": days_since_issued,
                    "days_until_expiry": days_until_expiry,
                    "sans_count": len(sans),
                    "flags": flags
                }

    except Exception as e:
        return {
            "has_ssl": False,
            "error": str(e),
            "issuer": None,
            "flags": [f"SSL Handshake failed or server does not support HTTPS ({type(e).__name__})"]
        }


def fetch_domain_whois_rdap(domain: str, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Fetches official domain registration data via ICANN Registration Data Access Protocol (RDAP).
    Extracts Domain Age, Registrar, and detects Newly Registered Domains (<30 days).
    """
    base_domain = extract_base_domain(domain)
    rdap_url = f"https://rdap.org/domain/{base_domain}"
    flags = []

    try:
        req = urllib.request.Request(
            rdap_url,
            headers={"User-Agent": "PhishGuard-Threat-Intel/2.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                
                events = data.get("events", [])
                reg_date_str = None
                for ev in events:
                    if ev.get("eventAction") in ["registration", "created"]:
                        reg_date_str = ev.get("eventDate")
                        break

                # Extract registrar
                entities = data.get("entities", [])
                registrar = "Unknown Registrar"
                for ent in entities:
                    if "registrar" in ent.get("roles", []):
                        vcard = ent.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    registrar = item[3]
                                    break

                # Compute Age
                domain_age_days = None
                if reg_date_str:
                    try:
                        # Format is usually YYYY-MM-DDTHH:MM:SSZ
                        clean_date = reg_date_str.split("T")[0]
                        reg_dt = datetime.strptime(clean_date, "%Y-%m-%d")
                        domain_age_days = (datetime.utcnow() - reg_dt).days

                        if domain_age_days <= 14:
                            flags.append(f"CRITICAL: Domain is newly registered ({domain_age_days} days old)")
                        elif domain_age_days <= 45:
                            flags.append(f"WARNING: Fresh domain registered recently ({domain_age_days} days old)")
                    except Exception:
                        pass

                return {
                    "success": True,
                    "domain": base_domain,
                    "registrar": registrar,
                    "registration_date": reg_date_str,
                    "domain_age_days": domain_age_days,
                    "is_newly_registered": bool(domain_age_days is not None and domain_age_days <= 45),
                    "flags": flags
                }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            flags.append("Domain not found in RDAP registry (Unregistered or brand new TLD)")
        return {
            "success": False,
            "domain": base_domain,
            "error": f"RDAP HTTP {e.code}",
            "flags": flags
        }
    except Exception as e:
        return {
            "success": False,
            "domain": base_domain,
            "error": str(e),
            "flags": flags
        }


def query_virustotal_reputation(target_url: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Queries VirusTotal v3 API for URL threat reputation across 70+ AV scanning engines.
    If no API key is provided, returns graceful status.
    """
    if not api_key:
        return {
            "configured": False,
            "message": "VirusTotal API key not configured. Add key in sidebar for live multi-engine AV verification.",
            "malicious_count": 0,
            "total_engines": 0
        }

    try:
        # VirusTotal v3 URL ID is base64 encoded URL without padding
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        vt_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        req = urllib.request.Request(
            vt_endpoint,
            headers={
                "x-apikey": api_key.strip(),
                "User-Agent": "PhishGuard-AI-Scanner/2.0"
            }
        )

        with urllib.request.urlopen(req, timeout=5.0) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)

                flags = []
                if malicious > 0:
                    flags.append(f"VirusTotal: Flagged as MALICIOUS by {malicious} security vendors")
                elif suspicious > 0:
                    flags.append(f"VirusTotal: Flagged as SUSPICIOUS by {suspicious} security vendors")

                return {
                    "configured": True,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "harmless_count": harmless,
                    "total_engines": sum(stats.values()),
                    "flags": flags
                }
    except Exception as e:
        return {
            "configured": True,
            "error": str(e),
            "malicious_count": 0
        }


def get_live_threat_intelligence(url: str, vt_api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Consolidates live network intelligence for a target URL:
    1. SSL/TLS Certificate Audit
    2. ICANN RDAP Domain Age & Registrar Lookup
    3. Multi-Engine VirusTotal Reputation
    """
    parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
    hostname = parsed.hostname or ""

    ssl_info = audit_ssl_certificate(hostname)
    whois_info = fetch_domain_whois_rdap(hostname)
    vt_info = query_virustotal_reputation(url, vt_api_key)

    # Consolidated flags
    all_flags = []
    all_flags.extend(ssl_info.get("flags", []))
    all_flags.extend(whois_info.get("flags", []))
    all_flags.extend(vt_info.get("flags", []))

    # Calculate live threat score modifier
    risk_bonus = 0
    if whois_info.get("is_newly_registered"):
        risk_bonus += 35
    if vt_info.get("malicious_count", 0) > 0:
        risk_bonus += 50
    elif vt_info.get("suspicious_count", 0) > 0:
        risk_bonus += 25
    if ssl_info.get("days_since_issued") is not None and ssl_info.get("days_since_issued") <= 7:
        risk_bonus += 15

    return {
        "hostname": hostname,
        "ssl_audit": ssl_info,
        "whois_rdap": whois_info,
        "virustotal": vt_info,
        "live_flags": all_flags,
        "live_risk_bonus": risk_bonus
    }
