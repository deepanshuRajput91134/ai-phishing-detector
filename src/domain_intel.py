import re
import difflib
from typing import Dict, Any, List, Optional

# Top 60 most phished & imitated global brands (Finance, Tech, Crypto, Logistics)
MONITORED_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "twitter", "chase", "wellsfargo",
    "bankofamerica", "citibank", "capitalone", "hsbc", "barclays", "santander",
    "binance", "coinbase", "metamask", "kraken", "blockchain", "dhl", "fedex",
    "ups", "usps", "dropbox", "adobe", "spotify", "steam", "telegram",
    "roblox", "ebay", "walmart", "target", "irs", "gov", "outlook", "office365",
    "yahoo", "icloud", "att", "verizon", "tmobile", "docusign"
]

COMMON_HOMOGLYPHS = {
    '0': 'o', '1': 'l', 'vv': 'w', 'rn': 'm', '@': 'a', '$': 's'
}


def normalize_homoglyphs(text: str) -> str:
    """Normalizes common visual character substitutions (e.g. paypa1 -> paypal, rnicrosoft -> microsoft)."""
    normalized = text.lower()
    for fake, real in COMMON_HOMOGLYPHS.items():
        normalized = normalized.replace(fake, real)
    return normalized


def analyze_brand_impersonation(hostname: str) -> Dict[str, Any]:
    """
    Detects typosquatting, combosquatting, homoglyph substitutions,
    and subdomain traps against monitored high-value targets.
    """
    clean_host = hostname.lower().strip()
    if clean_host.startswith("www."):
        clean_host = clean_host[4:]

    parts = clean_host.split(".")
    if len(parts) >= 2:
        main_domain = parts[-2]
        full_subdomains = ".".join(parts[:-2])
    else:
        main_domain = clean_host
        full_subdomains = ""

    # Check Punycode first (IDN homograph attack)
    if clean_host.startswith("xn--") or ".xn--" in clean_host:
        return {
            "impersonated": True,
            "target_brand": "Unknown (Punycode / IDN)",
            "attack_type": "IDN Homograph Attack",
            "risk_bonus": 55,
            "description": "Uses Punycode ('xn--') encoding to disguise international characters as legitimate Latin letters"
        }

    # Split domain into tokens by hyphens, underscores, dots
    domain_tokens = [t for t in re.split(r"[-_.]", main_domain) if t]
    subdomain_tokens = [t for t in re.split(r"[-_.]", full_subdomains) if t]
    all_tokens = domain_tokens + subdomain_tokens

    for brand in MONITORED_BRANDS:
        # Check if the brand name is placed in subdomains (Subdomain Trap)
        if full_subdomains and (brand in full_subdomains):
            return {
                "impersonated": True,
                "target_brand": brand.capitalize(),
                "attack_type": "Subdomain Brand Spoofing",
                "risk_bonus": 45,
                "description": f"Brand name '{brand.capitalize()}' placed inside subdomains to deceive user address bars"
            }

        # Check each token for exact match with hyphenation (Combosquatting)
        if brand in domain_tokens and len(domain_tokens) > 1:
            return {
                "impersonated": True,
                "target_brand": brand.capitalize(),
                "attack_type": "Combosquatting / Brand Lure",
                "risk_bonus": 40,
                "description": f"Domain couples brand '{brand.capitalize()}' with deceptive keywords in '{main_domain}'"
            }

        # Check homoglyph & typosquatting across all domain tokens
        for token in domain_tokens:
            norm_token = normalize_homoglyphs(token)
            
            # Homoglyph direct match (e.g., paypa1 -> paypal)
            if norm_token == brand and token != brand:
                return {
                    "impersonated": True,
                    "target_brand": brand.capitalize(),
                    "attack_type": "Homoglyph Character Substitution",
                    "risk_bonus": 50,
                    "description": f"Character substitution detected: '{token}' disguises as legitimate brand '{brand.capitalize()}'"
                }

            # Levenshtein / Similarity check
            similarity = difflib.SequenceMatcher(None, norm_token, brand).ratio()
            if 0.78 <= similarity < 1.0 and len(token) >= 4:
                return {
                    "impersonated": True,
                    "target_brand": brand.capitalize(),
                    "attack_type": "Typosquatting Impersonation",
                    "similarity_score": round(similarity * 100, 1),
                    "risk_bonus": 50,
                    "description": f"Token '{token}' has {round(similarity*100)}% visual similarity to brand '{brand.capitalize()}'"
                }

    return {
        "impersonated": False,
        "target_brand": None,
        "attack_type": None,
        "risk_bonus": 0,
        "description": "No direct brand typosquatting detected."
    }
