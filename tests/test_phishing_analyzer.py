import unittest

from phishing_analyzer import (
    Message,
    analyze_message,
    extract_urls,
    format_analysis_text,
    parse_form_body,
)


class PhishingAnalyzerTests(unittest.TestCase):
    def test_extract_urls(self):
        text = "Visit https://example.com and http://test.org/path now"
        self.assertEqual(extract_urls(text), ["https://example.com", "http://test.org/path"])

    def test_risky_tld_link_marked_suspicious(self):
        message = Message(
            sender="help@service-update.top",
            subject="Urgent account update",
            body="Verify now at https://service-update.top/login",
            message_id="t1",
        )
        result = analyze_message(message)
        self.assertIn("https://service-update.top/login", result.suspicious_links)
        self.assertTrue(any("risky top-level domain" in flag for flag in result.red_flags))

    def test_safe_link_not_marked_suspicious(self):
        message = Message(
            sender="support@amazon.com",
            subject="Order shipped",
            body="Track package at https://amazon.com/orders",
            message_id="t2",
        )
        result = analyze_message(message)
        self.assertEqual(result.suspicious_links, [])
        self.assertEqual(result.verdict, "LOW RISK")

    def test_impersonation_flag(self):
        message = Message(
            sender="alert@amazon-secure-check.click",
            subject="Amazon account notice",
            body="Login now to verify your Amazon account",
            message_id="t3",
        )
        result = analyze_message(message)
        self.assertTrue(any("Possible impersonation" in f for f in result.red_flags))

    def test_gui_output_format_contains_key_sections(self):
        message = Message(
            sender="service@netflix-security-check.click",
            subject="Immediate action needed",
            body="Verify now at https://netflix-billing-check.click/login",
            message_id="gui-1",
        )
        result = analyze_message(message)
        report_text = format_analysis_text(result)

        self.assertIn("Verdict:", report_text)
        self.assertIn("Suspicious Links:", report_text)
        self.assertIn("Red Flags:", report_text)

    def test_web_form_parser_decodes_encoded_values(self):
        parsed = parse_form_body("sender=user%40mail.com&subject=Hello+World&body=Check+this")
        self.assertEqual(parsed["sender"], "user@mail.com")
        self.assertEqual(parsed["subject"], "Hello World")
        self.assertEqual(parsed["body"], "Check this")


if __name__ == "__main__":
    unittest.main()
