import tempfile
import unittest
from pathlib import Path

from scanner import scan_file


class SensitiveDataScannerTests(unittest.TestCase):
    def scan_text(self, content: str):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "sample.txt"
            sample.write_text(content, encoding="utf-8")
            return scan_file(sample)

    def test_detects_email_address(self):
        findings = self.scan_text("Contact: analyst@example.org")
        self.assertIn("EMAIL_ADDRESS", {item.rule_id for item in findings})

    def test_detects_aws_access_key_pattern(self):
        findings = self.scan_text("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF")
        self.assertIn("AWS_ACCESS_KEY_ID", {item.rule_id for item in findings})

    def test_detects_credential_assignment_without_exposing_value(self):
        findings = self.scan_text("API_KEY=not-a-real-secret-123")
        self.assertIn("CREDENTIAL_ASSIGNMENT", {item.rule_id for item in findings})
        rendered = " ".join(item.description for item in findings)
        self.assertNotIn("not-a-real-secret-123", rendered)

    def test_ignores_common_password_placeholder(self):
        findings = self.scan_text("PASSWORD=changeme")
        self.assertNotIn("CREDENTIAL_ASSIGNMENT", {item.rule_id for item in findings})

    def test_detects_private_key_header(self):
        findings = self.scan_text("-----BEGIN PRIVATE KEY-----")
        self.assertIn("PRIVATE_KEY_HEADER", {item.rule_id for item in findings})


if __name__ == "__main__":
    unittest.main()
