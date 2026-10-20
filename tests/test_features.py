import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from features import (
    calculate_entropy,
    extract_url_features,
    extract_url_red_flags,
    extract_urls_from_text,
    extract_email_metadata_features
)


class TestFeatures(unittest.TestCase):
    def test_shannon_entropy(self):
        # Empty string
        self.assertEqual(calculate_entropy(""), 0.0)
        # Uniform single char
        self.assertEqual(calculate_entropy("aaaaa"), 0.0)
        # Random DGA string has higher entropy than simple repetitive string
        self.assertGreater(calculate_entropy("x8q2k9z1m4b7"), calculate_entropy("google.com"))

    def test_extract_url_features(self):
        url = "http://192.168.1.100:8080/login.php?user=admin"
        feats = extract_url_features(url)
        self.assertEqual(feats["has_ip"], 1.0)
        self.assertEqual(feats["has_https"], 0.0)
        self.assertGreater(feats["suspicious_keyword_count"], 0)

    def test_extract_urls_from_text(self):
        text = "Please check https://example.com/login and http://test.org for updates."
        urls = extract_urls_from_text(text)
        self.assertIn("https://example.com/login", urls)
        self.assertIn("http://test.org", urls)

    def test_extract_email_metadata_features(self):
        subject = "URGENT: ACTION REQUIRED IMMEDIATELY!"
        body = "Dear Customer, Please verify your password and bank card details within 24 hours."
        meta = extract_email_metadata_features(subject, body)
        self.assertGreater(meta["urgency_score"], 0)
        self.assertGreater(meta["credential_score"], 0)
        self.assertEqual(meta["impersonal_greeting"], 1.0)


if __name__ == "__main__":
    unittest.main()
