import email
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
import re
from typing import Dict, Any, List, Optional

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf", "hta",
    "iso", "img", "vhd", "lnk", "pif", "xlsm", "docm", "pptm", "jar"
}

ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "tar", "gz", "bz2", "xz"}


def extract_domain_from_email_address(addr: str) -> str:
    """Extracts domain part from an email address like 'John Doe <john@example.com>'."""
    match = re.search(r"@([\w\.-]+)", addr)
    return match.group(1).lower() if match else ""


def parse_eml_file(eml_bytes: bytes) -> Dict[str, Any]:
    """
    Parses a raw .eml (RFC 822) file and extracts headers, bodies,
    email spoofing indicators, and attachments.
    """
    msg = BytesParser(policy=policy.default).parsebytes(eml_bytes)

    # 1. Essential Headers
    subject = msg.get("Subject", "") or ""
    from_header = msg.get("From", "") or ""
    to_header = msg.get("To", "") or ""
    date_header = msg.get("Date", "") or ""
    reply_to = msg.get("Reply-To", "") or ""
    return_path = msg.get("Return-Path", "") or ""

    from_domain = extract_domain_from_email_address(from_header)
    reply_to_domain = extract_domain_from_email_address(reply_to)
    return_path_domain = extract_domain_from_email_address(return_path)

    # 2. Domain Alignment / Spoofing Check
    spoofing_flags = []
    if reply_to_domain and from_domain and (reply_to_domain != from_domain):
        spoofing_flags.append(
            f"Sender Mismatch: From domain is '{from_domain}', but Reply-To redirects replies to '{reply_to_domain}'"
        )
    if return_path_domain and from_domain and (return_path_domain != from_domain):
        spoofing_flags.append(
            f"Return-Path Mismatch: Bounces redirect to '{return_path_domain}' instead of '{from_domain}' (Possible SPF bypass)"
        )

    # 3. Authentication Headers (SPF / DKIM / DMARC)
    auth_results = msg.get("Authentication-Results", "") or ""
    received_spf = msg.get("Received-SPF", "") or ""

    spf_pass = "pass" in received_spf.lower() or "spf=pass" in auth_results.lower()
    dkim_pass = "dkim=pass" in auth_results.lower()
    dmarc_pass = "dmarc=pass" in auth_results.lower()

    if "spf=fail" in auth_results.lower() or "fail" in received_spf.lower():
        spoofing_flags.append("SPF Authentication explicitly FAILED")
    if "dkim=fail" in auth_results.lower():
        spoofing_flags.append("DKIM Cryptographic Signature FAILED")
    if "dmarc=fail" in auth_results.lower():
        spoofing_flags.append("DMARC Policy Enforcement FAILED")

    # 4. Extract Body & Embedded URLs
    text_parts = []
    html_parts = []
    attachments = []

    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = str(part.get_content_disposition() or "").lower()

        if disposition == "attachment" or part.get_filename():
            filename = part.get_filename() or "unknown_file"
            ext = filename.split(".")[-1].lower() if "." in filename else ""
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0

            is_dangerous = ext in DANGEROUS_EXTENSIONS
            is_archive = ext in ARCHIVE_EXTENSIONS

            attachments.append({
                "filename": filename,
                "extension": ext,
                "size_bytes": size,
                "is_dangerous": is_dangerous,
                "is_archive": is_archive
            })

            if is_dangerous:
                spoofing_flags.append(f"Dangerous executable attachment detected: '{filename}' (.{ext})")
            elif is_archive:
                spoofing_flags.append(f"Compressed archive attachment detected: '{filename}' (often used to evade gateway filters)")

        elif content_type == "text/plain":
            payload = part.get_payload(decode=True)
            if payload:
                text_parts.append(payload.decode(errors="replace"))
        elif content_type == "text/html":
            payload = part.get_payload(decode=True)
            if payload:
                html_parts.append(payload.decode(errors="replace"))

    full_text_body = "\n".join(text_parts)
    full_html_body = "\n".join(html_parts)
    effective_body = full_text_body if full_text_body.strip() else full_html_body

    # Extract hyperlinks from HTML <a> tags specifically
    html_hrefs = re.findall(r'<a\s+(?:[^>]*?\s+)?href=["\'](https?://[^"\']+)["\']', full_html_body, re.IGNORECASE)

    return {
        "headers": {
            "subject": subject,
            "from": from_header,
            "to": to_header,
            "date": date_header,
            "reply_to": reply_to,
            "return_path": return_path,
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain
        },
        "auth_security": {
            "spf_pass": spf_pass,
            "dkim_pass": dkim_pass,
            "dmarc_pass": dmarc_pass,
            "auth_results": auth_results[:180]
        },
        "spoofing_flags": spoofing_flags,
        "attachments": attachments,
        "body_text": effective_body,
        "html_links": list(set(html_hrefs))
    }
