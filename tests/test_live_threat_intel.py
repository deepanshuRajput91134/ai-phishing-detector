import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from live_threat_intel import (
    extract_base_domain,
    audit_ssl_certificate,
    fetch_domain_whois_rdap,
    query_virustotal_reputation,
    get_live_threat_intelligence
)


class TestLiveThreatIntel(unittest.TestCase):
    def test_extract_base_domain(self):
        self.assertEqual(extract_base_domain("auth.login.paypal.com"), "paypal.com")
        self.assertEqual(extract_base_domain("www.google.com"), "google.com")
        self.assertEqual(extract_base_domain("secure-update.xyz"), "secure-update.xyz")

    def test_ssl_audit_ip_address(self):
        res = audit_ssl_certificate("192.168.1.1")
        self.assertFalse(res["has_ssl"])
        self.assertIn("raw IP", res["flags"][0])

    def test_vt_unconfigured(self):
        res = query_virustotal_reputation("https://example.com", api_key=None)
        self.assertFalse(res["configured"])
        self.assertEqual(res["malicious_count"], 0)

    def test_live_threat_intelligence_orchestration(self):
        res = get_live_threat_intelligence("http://192.168.1.50/login.php")
        self.assertEqual(res["hostname"], "192.168.1.50")
        self.assertIn("ssl_audit", res)
        self.assertIn("whois_rdap", res)
        self.assertIn("virustotal", res)
        self.assertIsInstance(res["live_risk_bonus"], int)


if __name__ == "__main__":
    unittest.main()
