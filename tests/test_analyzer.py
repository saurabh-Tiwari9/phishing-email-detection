import unittest
from pathlib import Path
from phishing_analyzer import analyze_email

ROOT = Path(__file__).resolve().parents[1]

class AnalyzerTests(unittest.TestCase):
    def test_suspicious_sample_has_high_risk(self):
        report = analyze_email(ROOT / "samples" / "suspicious_sample.eml")
        self.assertGreaterEqual(report["risk_score"], 50)
        self.assertEqual(report["verdict"], "Likely phishing")
        self.assertTrue(report["urls"])

    def test_ordinary_sample_is_lower_risk(self):
        report = analyze_email(ROOT / "samples" / "ordinary_sample.eml")
        self.assertLess(report["risk_score"], 25)
        self.assertEqual(report["verdict"], "Low indicators detected")

if __name__ == "__main__":
    unittest.main()
