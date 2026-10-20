import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from predictor import PhishingDetector


class TestPredictor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = PhishingDetector()

    def test_predict_legit_url(self):
        res = self.detector.predict_url("https://developer.mozilla.org/en-US/docs/Web")
        self.assertIn("risk_score", res)
        self.assertLess(res["risk_score"], 50)
        self.assertFalse(res["is_phishing"])

    def test_predict_phishing_url(self):
        res = self.detector.predict_url("http://paypa1-security-verification.xyz/login.php")
        self.assertIn("risk_score", res)
        self.assertGreaterEqual(res["risk_score"], 70)
        self.assertTrue(res["is_phishing"])
        self.assertTrue(res["brand_intelligence"]["impersonated"])

    def test_predict_email(self):
        subject = "URGENT: Immediate Account Suspension Notice"
        body = "Dear Customer, Your account is locked. Verify password within 24 hours: http://192.168.1.1/login"
        res = self.detector.predict_email(subject, body)
        self.assertIn("risk_score", res)
        self.assertGreaterEqual(res["risk_score"], 60)
        self.assertGreater(len(res["red_flags"]), 0)


if __name__ == "__main__":
    unittest.main()
