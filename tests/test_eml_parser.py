import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from eml_parser import parse_eml_file, extract_domain_from_email_address


class TestEmlParser(unittest.TestCase):
    def test_extract_domain(self):
        self.assertEqual(extract_domain_from_email_address("Support <security@paypal.com>"), "paypal.com")
        self.assertEqual(extract_domain_from_email_address("admin@bankofamerica.com"), "bankofamerica.com")

    def test_parse_spoofed_eml(self):
        eml_raw = b"""From: Official Bank <security@trusted-bank.com>
To: victim@example.com
Subject: Urgent Security Notice
Reply-To: phisher@hacker-server.xyz
Authentication-Results: spf=fail; dkim=fail; dmarc=fail
Content-Type: text/plain

Dear Customer, verify your credentials here: https://hacker-server.xyz/login
"""
        parsed = parse_eml_file(eml_raw)
        self.assertEqual(parsed["headers"]["from_domain"], "trusted-bank.com")
        self.assertEqual(parsed["headers"]["reply_to_domain"], "hacker-server.xyz")
        # Should flag mismatch and auth fail
        self.assertTrue(any("Sender Mismatch" in f for f in parsed["spoofing_flags"]))
        self.assertFalse(parsed["auth_security"]["spf_pass"])
        self.assertFalse(parsed["auth_security"]["dkim_pass"])


if __name__ == "__main__":
    unittest.main()
