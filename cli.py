import argparse
import sys
import os

# Add src to pythonpath
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from predictor import PhishingDetector


def format_risk_badge(score: int, verdict: str) -> str:
    if score >= 70:
        return f"\033[91m[!] {verdict} (Risk: {score}/100)\033[0m"
    elif score >= 40:
        return f"\033[93m[*] {verdict} (Risk: {score}/100)\033[0m"
    else:
        return f"\033[92m[✓] {verdict} (Risk: {score}/100)\033[0m"


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard Enterprise AI - Threat Scanner & Live Network Intel"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", type=str, help="Single URL to scan for phishing patterns")
    group.add_argument("--email-file", type=str, help="Path to raw email or .eml file")
    group.add_argument("--email-text", type=str, help="Raw email text to scan (subject + body)")

    parser.add_argument("--subject", type=str, default="", help="Email Subject (optional if using --email-text)")
    parser.add_argument("--live-intel", action="store_true", help="Enable live SSL audit, ICANN RDAP domain age, and threat feed lookups")
    parser.add_argument("--vt-key", type=str, default=None, help="Optional VirusTotal API key for live AV engine reputation")

    args = parser.parse_args()
    detector = PhishingDetector()

    if args.url:
        print("\n" + "="*58)
        print("          AI URL & LIVE THREAT INTELLIGENCE SCAN")
        print("="*58)
        print(f"Target URL: {args.url}\n")
        res = detector.predict_url(args.url, enable_live_intel=args.live_intel, vt_api_key=args.vt_key)
        print(format_risk_badge(res["risk_score"], res["verdict"]))
        print(f"Phishing Probability: {res['probability']*100:.1f}%\n")

        # Brand Alert
        brand = res.get("brand_intelligence", {})
        if brand.get("impersonated"):
            print("\033[91m[TARGETED BRAND SPOOFING]\033[0m")
            print(f"  • Protected Brand: {brand.get('target_brand')}")
            print(f"  • Attack Vector:   {brand.get('attack_type')}")
            print(f"  • Threat Details:  {brand.get('description')}\n")

        # Live Network Intelligence
        live = res.get("live_threat_intel")
        if live:
            print("\033[94m[LIVE NETWORK INTELLIGENCE]\033[0m")
            ssl_info = live.get("ssl_audit", {})
            whois_info = live.get("whois_rdap", {})
            vt_info = live.get("virustotal", {})

            if whois_info.get("domain_age_days") is not None:
                print(f"  • Domain Age:      {whois_info['domain_age_days']} days (Registrar: {whois_info.get('registrar')})")
            if ssl_info.get("has_ssl"):
                print(f"  • SSL Issuer:      {ssl_info.get('issuer')} (Issued {ssl_info.get('days_since_issued')} days ago)")
            if vt_info.get("configured"):
                print(f"  • VirusTotal:      {vt_info.get('malicious_count')}/{vt_info.get('total_engines')} vendors flagged malicious")
            print("")

        if res["red_flags"]:
            print("Flagged Threat Indicators:")
            for rf in res["red_flags"]:
                print(f"  • {rf}")
        else:
            print("No high-risk structural anomalies detected.")

        print("\nExtracted Lexical Signals:")
        f = res["features"]
        print(f"  • Domain Length:     {int(f['domain_len'])}")
        print(f"  • Domain Entropy:    {f['domain_entropy']:.2f}")
        print(f"  • Subdomain Depth:   {int(f['subdomain_count'])}")
        print(f"  • Insecure HTTP:     {'Yes' if f['has_https']==0 else 'No (HTTPS)'}")
        print(f"  • Raw IP in Host:    {'Yes' if f['has_ip']==1 else 'No'}")
        print("="*58 + "\n")

    elif args.email_file:
        if args.email_file.endswith(".eml"):
            print("\n" + "="*58)
            print("        RFC 822 (.EML) RAW EMAIL & HEADER AUDIT")
            print("="*58)
            with open(args.email_file, "rb") as f:
                eml_bytes = f.read()
            res = detector.scan_eml(eml_bytes, enable_live_intel=args.live_intel)
            print(format_risk_badge(res["composite_risk_score"], res["composite_verdict"]))
            h = res["headers"]
            print(f"From:     {h.get('from')}")
            print(f"Reply-To: {h.get('reply_to') or 'Same as From'}")
            print(f"Subject:  {h.get('subject')}\n")

            auth = res["auth_security"]
            print(f"Authentication: SPF: {'PASS' if auth['spf_pass'] else 'FAIL'} | DKIM: {'PASS' if auth['dkim_pass'] else 'FAIL'}")

            if res["spoofing_flags"]:
                print("\nSpoofing & Security Flags:")
                for sf in res["spoofing_flags"]:
                    print(f"  • {sf}")

            if res["attachments"]:
                print("\nAttachments:")
                for att in res["attachments"]:
                    status = "DANGEROUS" if att["is_dangerous"] else "Normal"
                    print(f"  • {att['filename']} ({att['size_bytes']} bytes) - {status}")

            print("="*58 + "\n")
        else:
            with open(args.email_file, "r", encoding="utf-8") as f:
                content = f.read()
            scan_text_email(detector, args.subject, content, args.live_intel)

    elif args.email_text:
        scan_text_email(detector, args.subject, args.email_text, args.live_intel)


def scan_text_email(detector, subject, content, live_intel=False):
    body = content
    if not subject and "\n" in content:
        lines = content.split("\n", 1)
        subject = lines[0].strip()
        body = lines[1].strip()

    print("\n" + "="*58)
    print("       AI COMPOSITE EMAIL SECURITY SCAN")
    print("="*58)
    print(f"Subject: {subject[:70]}")
    print(f"Body:    {body[:100]}...\n")

    res = detector.scan_full_email(subject, body, enable_live_intel=live_intel)
    print(format_risk_badge(res["composite_risk_score"], res["composite_verdict"]))
    print(f"Composite Risk Score: {res['composite_risk_score']}/100\n")

    email_analysis = res["email_analysis"]
    print(f"Email Content Risk: {email_analysis['risk_score']}/100")
    if email_analysis["red_flags"]:
        print("Email Red Flags:")
        for rf in email_analysis["red_flags"]:
            print(f"  • {rf}")

    if res["extracted_urls"]:
        print(f"\nEmbedded Links Found ({len(res['extracted_urls'])}):")
        for url_res in res["url_analysis"]:
            badge = format_risk_badge(url_res.get("risk_score", 0), url_res.get("verdict", "N/A"))
            print(f"  - {url_res['target']}")
            print(f"    {badge}")
            if url_res.get("red_flags"):
                for rf in url_res["red_flags"]:
                    print(f"      • {rf}")
    else:
        print("\nEmbedded Links: None detected.")

    print("="*58 + "\n")


if __name__ == "__main__":
    main()
