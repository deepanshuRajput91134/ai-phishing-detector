import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from domain_intel import analyze_brand_impersonation, normalize_homoglyphs


class TestDomainIntel(unittest.TestCase):
    def test_normalize_homoglyphs(self):
        self.assertEqual(normalize_homoglyphs("paypa1"), "paypal")
        self.assertEqual(normalize_homoglyphs("g00gle"), "google")
        self.assertEqual(normalize_homoglyphs("rnicrosoft"), "microsoft")

    def test_homoglyph_brand_spoofing(self):
        res = analyze_brand_impersonation("paypa1-security.com")
        self.assertTrue(res["impersonated"])
        self.assertEqual(res["target_brand"], "Paypal")
        self.assertIn("Homoglyph", res["attack_type"])

    def test_combosquatting(self):
        res = analyze_brand_impersonation("chase-online-verify.xyz")
        self.assertTrue(res["impersonated"])
        self.assertEqual(res["target_brand"], "Chase")

    def test_subdomain_trap(self):
        res = analyze_brand_impersonation("apple.com.secure-portal-99.top")
        self.assertTrue(res["impersonated"])
        self.assertEqual(res["target_brand"], "Apple")
        self.assertIn("Subdomain", res["attack_type"])

    def test_punycode_detection(self):
        res = analyze_brand_impersonation("xn--pple-43d.com")
        self.assertTrue(res["impersonated"])
        self.assertIn("Punycode", res["description"])

    def test_legitimate_domain(self):
        res = analyze_brand_impersonation("developer.mozilla.org")
        self.assertFalse(res["impersonated"])


if __name__ == "__main__":
    unittest.main()
