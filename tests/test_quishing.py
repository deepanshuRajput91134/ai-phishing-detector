import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from quishing import extract_qr_from_image, analyze_quishing_threat
from predictor import PhishingDetector


class TestQuishing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = PhishingDetector()

    def test_invalid_image_bytes(self):
        res = extract_qr_from_image(b"not an image")
        self.assertFalse(res["success"])
        self.assertFalse(res["found_qr"])

    def test_quishing_threat_no_qr(self):
        # 1x1 black pixel PNG
        dummy_png = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\xa7V\xfe\xae\x00\x00\x00\x00IEND\xaeB`\x82'
        res = analyze_quishing_threat(dummy_png, self.detector)
        self.assertFalse(res["quishing_detected"])
        self.assertEqual(res["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()
