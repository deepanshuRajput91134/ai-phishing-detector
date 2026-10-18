import re
import math
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple

# Common top-level domains frequently abused in phishing
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "work", 
    "click", "link", "country", "stream", "gdn", "mom", "rest", "kim"
}

# Common keywords found in phishing URL paths or subdomains
SUSPICIOUS_URL_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "authenticate", "confirm", "wallet",
    "ebayisapi", "webscr", "cmd", "password", "credential", "suspend",
    "authorize", "support", "billing", "invoice", "refund", "appleid"
]

# Urgency keywords and trigger phrases in email subjects and bodies
URGENT_PHRASES = [
    "urgent", "action required", "immediate action", "account suspended",
    "unauthorized access", "security alert", "suspicious activity",
    "locked", "verify immediately", "within 24 hours", "final notice",
    "deactivation", "terminated", "compromised", "unusual activity"
]

CREDENTIAL_LURES = [
    "enter your password", "confirm your identity", "verify your account",
    "update your payment", "click here to log in", "reset password",
    "validate credentials", "sign in to continue", "provide your pin",
    "social security", "card details", "otp"
]

FINANCIAL_LURES = [
    "wire transfer", "lottery", "won a prize", "claim reward",
    "tax refund", "cryptocurrency", "bitcoin", "overdue invoice",
    "payment received", "direct deposit", "inheritance", "million dollars"
]

IMPERSONAL_GREETINGS = [
    "dear customer", "dear client", "dear user", "dear member",
    "dear sir/madam", "dear sir", "dear madam", "dear account holder",
    "hello customer", "valued customer", "attention user"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "rebrand.ly", "cutt.ly"
}


def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string (measures randomness)."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


def extract_url_features(url: str) -> Dict[str, float]:
    """
    Extracts structural, lexical, and statistical features from a URL.
    Returns a dictionary of numeric features for ML model input.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        # Default scheme for parsing
        parseable_url = "http://" + url
    else:
        parseable_url = url

    parsed = urlparse(parseable_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_clean = (hostname + path + ("?" + query if query else "")).lower()

    # 1. Length features
    url_len = float(len(url))
    domain_len = float(len(hostname))
    path_len = float(len(path))
    query_len = float(len(query))

    # 2. Character counts
    dot_count = float(url.count("."))
    hyphen_count = float(url.count("-"))
    at_count = float(url.count("@"))
    question_count = float(url.count("?"))
    equal_count = float(url.count("="))
    underscore_count = float(url.count("_"))
    slash_count = float(url.count("/"))
    percent_count = float(url.count("%"))
    ampersand_count = float(url.count("&"))
    digits_count = float(sum(c.isdigit() for c in url))
    letters_count = float(sum(c.isalpha() for c in url))
    digit_ratio = (digits_count / url_len) if url_len > 0 else 0.0

    # 3. Domain features
    subdomains = hostname.split(".")
    subdomain_count = float(max(0, len(subdomains) - 2))

    # Check for IP address in hostname (IPv4)
    ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    has_ip = 1.0 if re.match(ip_pattern, hostname) else 0.0

    # Suspicious TLD
    tld = subdomains[-1] if len(subdomains) > 1 else ""
    is_suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # URL Shortener
    is_shortener = 1.0 if any(short in hostname for short in SHORTENER_DOMAINS) else 0.0

    # HTTPS presence
    has_https = 1.0 if url.lower().startswith("https://") else 0.0

    # Hyphen in domain (common typosquatting technique)
    has_hyphen_in_domain = 1.0 if "-" in hostname else 0.0

    # Double slash in path (redirection indicator)
    has_double_slash_redirect = 1.0 if "//" in path else 0.0

    # 4. Keyword counts in URL
    suspicious_keyword_count = float(sum(1 for kw in SUSPICIOUS_URL_KEYWORDS if kw in full_clean))

    # 5. Domain & URL Shannon Entropy
    domain_entropy = calculate_entropy(hostname)
    url_entropy = calculate_entropy(url)

    features = {
        "url_len": url_len,
        "domain_len": domain_len,
        "path_len": path_len,
        "query_len": query_len,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "at_count": at_count,
        "question_count": question_count,
        "equal_count": equal_count,
        "underscore_count": underscore_count,
        "slash_count": slash_count,
        "percent_count": percent_count,
        "ampersand_count": ampersand_count,
        "digit_ratio": digit_ratio,
        "subdomain_count": subdomain_count,
        "has_ip": has_ip,
        "is_suspicious_tld": is_suspicious_tld,
        "is_shortener": is_shortener,
        "has_https": has_https,
        "has_hyphen_in_domain": has_hyphen_in_domain,
        "has_double_slash_redirect": has_double_slash_redirect,
        "suspicious_keyword_count": suspicious_keyword_count,
        "domain_entropy": domain_entropy,
        "url_entropy": url_entropy,
    }
    return features


def extract_url_red_flags(url: str, features: Dict[str, float] = None) -> List[str]:
    """Generates human-readable red flags for explainability."""
    if features is None:
        features = extract_url_features(url)
    red_flags = []
    if features["has_ip"] > 0:
        red_flags.append("Direct IP address used instead of reputable domain name")
    if features["is_suspicious_tld"] > 0:
        red_flags.append("Domain uses an abuse-prone or suspicious top-level domain (TLD)")
    if features["is_shortener"] > 0:
        red_flags.append("URL shortener used to mask actual destination target")
    if features["has_hyphen_in_domain"] > 0 and features["suspicious_keyword_count"] > 0:
        red_flags.append("Domain contains brand-spoofing hyphenated patterns (e.g., paypal-secure)")
    if features["subdomain_count"] >= 3:
        red_flags.append(f"Excessive subdomains detected ({int(features['subdomain_count'])} levels)")
    if features["at_count"] > 0:
        red_flags.append("URL contains '@' character which can bypass browser visual checks")
    if features["has_double_slash_redirect"] > 0:
        red_flags.append("Suspicious '//' redirection pattern inside the URL path")
    if features["suspicious_keyword_count"] >= 2:
        red_flags.append(f"Contains multiple deceptive keywords in path/domain ({int(features['suspicious_keyword_count'])} detected)")
    if features["domain_entropy"] > 4.1:
        red_flags.append(f"High domain entropy ({features['domain_entropy']:.2f}) indicates potential randomly generated algorithm (DGA)")
    if features["has_https"] == 0:
        red_flags.append("Insecure plain HTTP connection (no SSL/TLS encryption)")
    return red_flags


def extract_urls_from_text(text: str) -> List[str]:
    """Extracts all HTTP/HTTPS and www URLs from an email body text."""
    url_pattern = r"(?:https?://|www\.)[^\s<>'\"`]+|[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-z]{2,}(?:/[^\s<>'\"`]*)?"
    matches = re.findall(url_pattern, text, re.IGNORECASE)
    cleaned = []
    for match in matches:
        # Strip trailing punctuation often caught in regex
        clean = match.rstrip(".,;!?:)]}\"'>")
        if "." in clean and len(clean) > 4:
            if not clean.startswith(("http://", "https://")):
                clean = "http://" + clean
            if clean not in cleaned:
                cleaned.append(clean)
    return cleaned


def extract_email_metadata_features(subject: str, body: str) -> Dict[str, float]:
    """Extracts linguistic, behavioral, and structural heuristic features from an email."""
    subject_lower = subject.lower()
    body_lower = body.lower()
    full_text = f"{subject_lower} {body_lower}"

    # 1. Structural lengths
    subject_len = float(len(subject))
    body_len = float(len(body))

    # 2. Capitalization and punctuation indicators
    subj_caps = sum(1 for c in subject if c.isupper())
    body_caps = sum(1 for c in body if c.isupper())
    subj_caps_ratio = (subj_caps / subject_len) if subject_len > 0 else 0.0
    body_caps_ratio = (body_caps / body_len) if body_len > 0 else 0.0

    exclamation_count = float(subject.count("!") + body.count("!"))
    question_count = float(subject.count("?") + body.count("?"))

    # 3. Behavioral intent signals
    urgency_score = float(sum(1 for phrase in URGENT_PHRASES if phrase in full_text))
    credential_score = float(sum(1 for phrase in CREDENTIAL_LURES if phrase in full_text))
    financial_score = float(sum(1 for phrase in FINANCIAL_LURES if phrase in full_text))
    impersonal_greeting = float(1 if any(g in body_lower[:150] for g in IMPERSONAL_GREETINGS) else 0)

    # 4. Links embedded
    extracted_urls = extract_urls_from_text(body)
    url_count = float(len(extracted_urls))
    has_ip_url = float(1 if any(re.search(r"//\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u) for u in extracted_urls) else 0)

    features = {
        "subject_len": subject_len,
        "body_len": body_len,
        "subj_caps_ratio": subj_caps_ratio,
        "body_caps_ratio": body_caps_ratio,
        "exclamation_count": exclamation_count,
        "question_count": question_count,
        "urgency_score": urgency_score,
        "credential_score": credential_score,
        "financial_score": financial_score,
        "impersonal_greeting": impersonal_greeting,
        "url_count": url_count,
        "has_ip_url": has_ip_url,
    }
    return features


def extract_email_red_flags(subject: str, body: str, metadata: Dict[str, float] = None) -> List[str]:
    """Generates human-readable red flags for email explainability."""
    if metadata is None:
        metadata = extract_email_metadata_features(subject, body)
    red_flags = []
    if metadata["urgency_score"] > 0:
        red_flags.append(f"High urgency psychological triggers detected ({int(metadata['urgency_score'])} phrases)")
    if metadata["credential_score"] > 0:
        red_flags.append("Explicit request or lure to verify passwords/credentials")
    if metadata["financial_score"] > 0:
        red_flags.append("Financial lures (invoice, prize, wire transfer, refund) detected")
    if metadata["impersonal_greeting"] > 0:
        red_flags.append("Generic impersonal salutation ('Dear Customer/Member') without personal identity")
    if metadata["has_ip_url"] > 0:
        red_flags.append("Email contains a raw IP-based web link instead of a named domain")
    if metadata["subj_caps_ratio"] > 0.4 and metadata["subject_len"] > 10:
        red_flags.append("Excessive capitalization in subject line (alarmist framing)")
    if metadata["exclamation_count"] >= 3:
        red_flags.append("Frequent exclamation marks used to induce panic or rush action")
    if metadata["url_count"] >= 3:
        red_flags.append(f"Multiple embedded web links ({int(metadata['url_count'])}) found in email body")
    return red_flags
