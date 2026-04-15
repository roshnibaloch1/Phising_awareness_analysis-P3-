from __future__ import annotations

import argparse
import csv
import json
import re
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from dataclasses import asdict, dataclass
from pathlib import Path
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
from typing import Iterable
from urllib.parse import unquote_plus, urlparse

SUSPICIOUS_KEYWORDS = {
    "urgency": {
        "urgent",
        "immediately",
        "act now",
        "within 24 hours",
        "suspended",
        "locked",
        "verify now",
        "final warning",
    },
    "credential_theft": {
        "password",
        "otp",
        "pin",
        "cvv",
        "social security",
        "ssn",
        "login",
        "sign in",
    },
    "financial": {
        "bank",
        "payment",
        "refund",
        "invoice",
        "gift card",
        "wire transfer",
        "crypto",
        "bitcoin",
    },
}

SUSPICIOUS_TLDS = {"zip", "top", "click", "work", "country", "gq", "tk"}
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
SAFE_BRAND_DOMAINS = {
    "microsoft": {"microsoft.com", "outlook.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com"},
    "google": {"google.com", "gmail.com"},
    "netflix": {"netflix.com"},
}
URL_PATTERN = re.compile(r"https?://[^\s)\]>'\"]+", re.IGNORECASE)


@dataclass
class Message:
    sender: str
    subject: str
    body: str
    message_id: str


@dataclass
class AnalysisResult:
    message_id: str
    sender: str
    extracted_links: list[str]
    suspicious_links: list[str]
    suspicious_keywords: list[str]
    red_flags: list[str]
    risk_score: int
    verdict: str
    explanation: str


def extract_urls(text: str) -> list[str]:
    return URL_PATTERN.findall(text)


def extract_keywords(text: str) -> list[str]:
    lowered = text.lower()
    hits: set[str] = set()
    for words in SUSPICIOUS_KEYWORDS.values():
        for word in words:
            if word in lowered:
                hits.add(word)
    return sorted(hits)


def domain_from_sender(sender: str) -> str:
    if "@" not in sender:
        return ""
    return sender.rsplit("@", 1)[-1].lower().strip()


def analyze_link(url: str) -> list[str]:
    issues: list[str] = []
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if not host:
        issues.append(f"Malformed link found: {url}")
        return issues

    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        issues.append(f"Link uses raw IP address: {url}")

    if "xn--" in host:
        issues.append(f"Link may use homograph/punycode trick: {url}")

    if host in SHORTENER_DOMAINS:
        issues.append(f"Link uses URL shortener (destination hidden): {url}")

    suffix = host.split(".")[-1] if "." in host else ""
    if suffix in SUSPICIOUS_TLDS:
        issues.append(f"Link uses risky top-level domain '.{suffix}': {url}")

    if "@" in parsed.netloc:
        issues.append(f"Link contains '@' in host section (obfuscation pattern): {url}")

    return issues


def collect_link_issues(links: list[str]) -> tuple[list[str], list[str]]:
    suspicious_links: list[str] = []
    issues: list[str] = []
    for url in links:
        url_issues = analyze_link(url)
        if url_issues:
            suspicious_links.append(url)
            issues.extend(url_issues)
    return suspicious_links, issues


def brand_impersonation_flags(text: str, sender_domain: str) -> list[str]:
    lowered = text.lower()
    flags: list[str] = []
    for brand, safe_domains in SAFE_BRAND_DOMAINS.items():
        if brand in lowered and sender_domain and sender_domain not in safe_domains:
            flags.append(
                f"Possible impersonation: message references {brand.title()} but sender domain is '{sender_domain}'"
            )
    return flags


def build_explanation(
    red_flags: list[str], suspicious_keywords: list[str], suspicious_links: list[str], verdict: str
) -> str:
    reasons: list[str] = []
    if suspicious_links:
        reasons.append("it contains suspicious or potentially deceptive links")
    if suspicious_keywords:
        reasons.append("it uses language commonly associated with phishing (urgency, credential, or payment prompts)")
    if red_flags:
        reasons.append("multiple behavioral and technical red flags were detected")

    if verdict == "LOW RISK":
        return (
            "No strong phishing indicators were found. Continue using normal caution and verify sender identity before sharing sensitive data."
        )

    if not reasons:
        return "No clear phishing indicators were found in this message. Stay cautious and verify sender identity before taking action."

    joined = ", ".join(reasons)
    return f"This message is unsafe because {joined}. Do not click links or share sensitive information until independently verified."


def analyze_message(message: Message) -> AnalysisResult:
    combined_text = f"{message.subject}\n{message.body}"
    extracted_links = extract_urls(combined_text)
    keyword_hits = extract_keywords(combined_text)
    sender_domain = domain_from_sender(message.sender)

    suspicious_links, link_flags = collect_link_issues(extracted_links)
    red_flags: list[str] = list(link_flags)

    red_flags.extend(brand_impersonation_flags(combined_text, sender_domain))

    lowered = combined_text.lower()
    if any(phrase in lowered for phrase in {"verify account", "confirm account", "login now"}):
        red_flags.append("Asks user to verify account via message link")
    if any(phrase in lowered for phrase in {"share otp", "send otp", "provide password", "confirm pin"}):
        red_flags.append("Requests sensitive credentials directly")
    if any(phrase in lowered for phrase in {"attachment", ".exe", ".html"}):
        red_flags.append("Attachment-related lure detected")

    risk_score = min(100, len(red_flags) * 12 + len(keyword_hits) * 4)
    if risk_score >= 70:
        verdict = "HIGH RISK PHISHING"
    elif risk_score >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    explanation = build_explanation(red_flags, keyword_hits, suspicious_links, verdict)

    return AnalysisResult(
        message_id=message.message_id,
        sender=message.sender,
        extracted_links=extracted_links,
        suspicious_links=suspicious_links,
        suspicious_keywords=keyword_hits,
        red_flags=red_flags,
        risk_score=risk_score,
        verdict=verdict,
        explanation=explanation,
    )


def load_messages_from_json(path: Path) -> list[Message]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("JSON input must be a list of messages")
    messages: list[Message] = []
    for i, row in enumerate(data, start=1):
        messages.append(
            Message(
                sender=str(row.get("sender", "unknown@example.com")),
                subject=str(row.get("subject", "")),
                body=str(row.get("body", "")),
                message_id=str(row.get("id", f"msg-{i}")),
            )
        )
    return messages


def load_messages_from_csv(path: Path) -> list[Message]:
    messages: list[Message] = []
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=1):
            messages.append(
                Message(
                    sender=str(row.get("sender", "unknown@example.com")),
                    subject=str(row.get("subject", "")),
                    body=str(row.get("body", "")),
                    message_id=str(row.get("id", f"msg-{i}")),
                )
            )
    return messages


def load_messages_from_text(path: Path) -> list[Message]:
    text = path.read_text(encoding="utf-8")
    chunks = [chunk.strip() for chunk in text.split("\n\n---\n\n") if chunk.strip()]
    messages: list[Message] = []
    for i, chunk in enumerate(chunks, start=1):
        lines = chunk.splitlines()
        sender = "unknown@example.com"
        subject = ""
        body_lines: list[str] = []

        for line in lines:
            if line.lower().startswith("sender:"):
                sender = line.split(":", 1)[1].strip()
            elif line.lower().startswith("subject:"):
                subject = line.split(":", 1)[1].strip()
            else:
                body_lines.append(line)

        messages.append(
            Message(
                sender=sender,
                subject=subject,
                body="\n".join(body_lines).strip(),
                message_id=f"msg-{i}",
            )
        )
    return messages


def load_messages(path: Path) -> list[Message]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return load_messages_from_json(path)
    if suffix == ".csv":
        return load_messages_from_csv(path)
    if suffix == ".txt":
        return load_messages_from_text(path)
    raise ValueError("Unsupported file format. Use .json, .csv, or .txt")


def analyze_messages(messages: Iterable[Message]) -> list[AnalysisResult]:
    return [analyze_message(message) for message in messages]


def print_report(results: list[AnalysisResult]) -> None:
    for result in results:
        print(f"\n=== Message: {result.message_id} ===")
        print(f"Sender: {result.sender}")
        print(f"Verdict: {result.verdict} (Score: {result.risk_score}/100)")

        print("Extracted Links:")
        if result.extracted_links:
            for link in result.extracted_links:
                print(f"  - {link}")
        else:
            print("  - None")

        print("Suspicious Links:")
        if result.suspicious_links:
            for link in result.suspicious_links:
                print(f"  - {link}")
        else:
            print("  - None")

        print("Suspicious Keywords:")
        if result.suspicious_keywords:
            for kw in result.suspicious_keywords:
                print(f"  - {kw}")
        else:
            print("  - None")

        print("Red Flags:")
        if result.red_flags:
            for flag in result.red_flags:
                print(f"  - {flag}")
        else:
            print("  - None")

        print("Why Unsafe:")
        print(f"  {result.explanation}")


def save_json_report(results: list[AnalysisResult], output_path: Path) -> None:
    payload = [asdict(result) for result in results]
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def sample_messages() -> list[Message]:
    return [
        Message(
            sender="security-alert@microsoft-support-login.top",
            subject="Urgent: Your Microsoft account will be suspended",
            body=(
                "We detected unusual login attempts. Verify now within 24 hours at "
                "https://microsoft-verify-login.top/secure and provide your OTP immediately."
            ),
            message_id="sample-1",
        ),
        Message(
            sender="billing@amazon.com",
            subject="Your order has shipped",
            body="Track your package at https://amazon.com/orders and contact support if needed.",
            message_id="sample-2",
        ),
        Message(
            sender="hr@company-payroll.com",
            subject="Salary revision notice",
            body=(
                "Please open the attachment salary-update.html and login now to confirm "
                "bank details for payment release."
            ),
            message_id="sample-3",
        ),
        Message(
            sender="support@paypaI.help",
            subject="Final warning: account locked",
            body=(
                "Your PayPal account is locked. Reset your password now: "
                "https://bit.ly/3xSecurePay"
            ),
            message_id="sample-4",
        ),
    ]


def format_analysis_text(result: AnalysisResult) -> str:
    extracted_links = "\n".join(f"- {link}" for link in result.extracted_links) or "- None"
    suspicious_links = "\n".join(f"- {link}" for link in result.suspicious_links) or "- None"
    keywords = "\n".join(f"- {kw}" for kw in result.suspicious_keywords) or "- None"
    red_flags = "\n".join(f"- {flag}" for flag in result.red_flags) or "- None"

    return (
        f"Message: {result.message_id}\n"
        f"Sender: {result.sender}\n"
        f"Verdict: {result.verdict} (Score: {result.risk_score}/100)\n\n"
        f"Extracted Links:\n{extracted_links}\n\n"
        f"Suspicious Links:\n{suspicious_links}\n\n"
        f"Suspicious Keywords:\n{keywords}\n\n"
        f"Red Flags:\n{red_flags}\n\n"
        f"Why Unsafe:\n{result.explanation}\n"
    )


def build_html_report(results: list[AnalysisResult]) -> str:
    cards: list[str] = []
    for result in results:
        links_html = "".join(f"<li>{escape(link)}</li>" for link in result.extracted_links) or "<li>None</li>"
        suspicious_links_html = "".join(f"<li>{escape(link)}</li>" for link in result.suspicious_links) or "<li>None</li>"
        keywords_html = "".join(f"<li>{escape(kw)}</li>" for kw in result.suspicious_keywords) or "<li>None</li>"
        flags_html = "".join(f"<li>{escape(flag)}</li>" for flag in result.red_flags) or "<li>None</li>"

        cards.append(
            f"""
            <article class=\"card\">
              <h3>Message: {escape(result.message_id)}</h3>
              <p><strong>Sender:</strong> {escape(result.sender)}</p>
              <p><strong>Verdict:</strong> {escape(result.verdict)} ({result.risk_score}/100)</p>
              <div class=\"grid\">
                <section><h4>Extracted Links</h4><ul>{links_html}</ul></section>
                <section><h4>Suspicious Links</h4><ul>{suspicious_links_html}</ul></section>
                <section><h4>Suspicious Keywords</h4><ul>{keywords_html}</ul></section>
                <section><h4>Red Flags</h4><ul>{flags_html}</ul></section>
              </div>
              <p><strong>Why Unsafe:</strong> {escape(result.explanation)}</p>
            </article>
            """
        )

    return f"""
        <!doctype html>
        <html lang=\"en\">
        <head>
            <meta charset=\"utf-8\" />
            <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
            <title>Phishing Awareness Analyzer</title>
            <style>
                :root {{
                    --bg: #f7f8fc;
                    --card: #ffffff;
                    --text: #1d2433;
                    --accent: #0066cc;
                    --warn: #9d3f00;
                }}
                body {{ margin: 0; font-family: Segoe UI, Arial, sans-serif; background: linear-gradient(135deg, #eef5ff, #f9f4ec); color: var(--text); }}
                main {{ max-width: 1080px; margin: 0 auto; padding: 20px; }}
                h1 {{ margin-top: 0; }}
                .panel {{ background: var(--card); border-radius: 12px; padding: 16px; box-shadow: 0 10px 24px rgba(0,0,0,.08); margin-bottom: 16px; }}
                .card {{ background: var(--card); border-left: 6px solid var(--accent); border-radius: 12px; padding: 16px; box-shadow: 0 8px 18px rgba(0,0,0,.06); margin-bottom: 16px; }}
                .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }}
                textarea {{ width: 100%; min-height: 140px; border: 1px solid #cfd8e3; border-radius: 8px; padding: 10px; font: inherit; }}
                input {{ width: 100%; border: 1px solid #cfd8e3; border-radius: 8px; padding: 10px; font: inherit; margin-bottom: 10px; }}
                button {{ background: var(--accent); color: white; border: 0; border-radius: 8px; padding: 10px 16px; cursor: pointer; }}
                small {{ color: #4b5563; }}
                .warn {{ color: var(--warn); }}
            </style>
        </head>
        <body>
            <main>
                <h1>Phishing Awareness Analyzer</h1>
                <p>Analyze email-style text for phishing indicators and red flags.</p>
                <section class=\"panel\">
                    <form method=\"post\" action=\"/analyze\">
                        <label for=\"sender\">Sender</label>
                        <input id=\"sender\" name=\"sender\" placeholder=\"alerts@example.com\" required />
                        <label for=\"subject\">Subject</label>
                        <input id=\"subject\" name=\"subject\" placeholder=\"Urgent account verification\" required />
                        <label for=\"body\">Body</label>
                        <textarea id=\"body\" name=\"body\" placeholder=\"Paste message body here\" required></textarea>
                        <br /><br />
                        <button type=\"submit\">Analyze Message</button>
                        <p><small>Tip: This tool is awareness-focused and rule-based.</small></p>
                    </form>
                </section>
                {''.join(cards)}
            </main>
        </body>
        </html>
        """


def parse_form_body(body: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for pair in body.split("&"):
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        values[unquote_plus(key)] = unquote_plus(value)
    return values


def run_web_app(port: int = 8000) -> None:
    class AnalyzerHandler(BaseHTTPRequestHandler):
        def _send_html(self, payload: str, status: int = 200) -> None:
            encoded = payload.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            if self.path == "/":
                self._send_html(build_html_report([]))
                return
            self._send_html("<h1>Not Found</h1>", status=404)

        def do_POST(self) -> None:
            if self.path != "/analyze":
                self._send_html("<h1>Not Found</h1>", status=404)
                return

            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8", errors="ignore")
            raw = parse_form_body(body)

            message = Message(
                sender=raw.get("sender", "unknown@example.com"),
                subject=raw.get("subject", ""),
                body=raw.get("body", ""),
                message_id="web-input",
            )
            result = analyze_message(message)
            self._send_html(build_html_report([result]))

    server = HTTPServer(("127.0.0.1", port), AnalyzerHandler)
    print(f"Web app running at http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def run_desktop_gui() -> None:
    root = tk.Tk()
    root.title("Phishing Awareness Analyzer")
    root.geometry("980x760")
    root.configure(bg="#f2f6fb")
    root.minsize(860, 640)

    title_frame = tk.Frame(root, bg="#f2f6fb", padx=12, pady=10)
    title_frame.pack(fill="x")
    tk.Label(
        title_frame,
        text="Phishing Awareness Analyzer",
        font=("Segoe UI", 16, "bold"),
        bg="#f2f6fb",
        fg="#1d2433",
    ).pack(side="left")

    verdict_var = tk.StringVar(value="Verdict: Not analyzed")
    score_var = tk.StringVar(value="Risk Score: 0/100")
    badge_var = tk.StringVar(value="Status: Awaiting input")

    verdict_frame = tk.Frame(root, bg="#dce6f5", padx=12, pady=8)
    verdict_frame.pack(fill="x", padx=12)
    verdict_label = tk.Label(verdict_frame, textvariable=verdict_var, font=("Segoe UI", 11, "bold"), bg="#dce6f5", fg="#1d2433")
    verdict_label.pack(side="left")
    tk.Label(verdict_frame, textvariable=score_var, font=("Segoe UI", 10), bg="#dce6f5", fg="#25344f").pack(side="left", padx=14)
    badge_label = tk.Label(verdict_frame, textvariable=badge_var, font=("Segoe UI", 10, "bold"), bg="#dce6f5", fg="#255f2a")
    badge_label.pack(side="right")

    form_frame = tk.Frame(root, padx=12, pady=10, bg="#f2f6fb")
    form_frame.pack(fill="x")

    tk.Label(form_frame, text="Sender", bg="#f2f6fb", fg="#1d2433").grid(row=0, column=0, sticky="w")
    sender_entry = tk.Entry(form_frame, width=90, relief="solid", bd=1)
    sender_entry.grid(row=0, column=1, sticky="we", pady=4)

    tk.Label(form_frame, text="Subject", bg="#f2f6fb", fg="#1d2433").grid(row=1, column=0, sticky="w")
    subject_entry = tk.Entry(form_frame, width=90, relief="solid", bd=1)
    subject_entry.grid(row=1, column=1, sticky="we", pady=4)

    tk.Label(form_frame, text="Body", bg="#f2f6fb", fg="#1d2433").grid(row=2, column=0, sticky="nw")
    body_text = ScrolledText(form_frame, height=9, width=80, relief="solid", bd=1)
    body_text.grid(row=2, column=1, sticky="we", pady=4)

    output = ScrolledText(root, height=20, width=110, relief="solid", bd=1)
    output.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    last_result: AnalysisResult | None = None

    def set_badge_from_verdict(verdict: str, score: int) -> None:
        if verdict == "HIGH RISK PHISHING":
            badge_var.set("Status: Dangerous")
            badge_label.configure(fg="#9d1b1b")
            verdict_frame.configure(bg="#f6d4d4")
            verdict_label.configure(bg="#f6d4d4")
            badge_label.configure(bg="#f6d4d4")
        elif verdict == "SUSPICIOUS":
            badge_var.set("Status: Needs verification")
            badge_label.configure(fg="#8c4f00")
            verdict_frame.configure(bg="#f8e9d2")
            verdict_label.configure(bg="#f8e9d2")
            badge_label.configure(bg="#f8e9d2")
        else:
            badge_var.set("Status: Low risk")
            badge_label.configure(fg="#255f2a")
            verdict_frame.configure(bg="#dcefdc")
            verdict_label.configure(bg="#dcefdc")
            badge_label.configure(bg="#dcefdc")
        score_var.set(f"Risk Score: {score}/100")

    def analyze_current_input() -> None:
        nonlocal last_result
        sender = sender_entry.get().strip() or "unknown@example.com"
        subject = subject_entry.get().strip()
        body = body_text.get("1.0", "end").strip()

        if not subject and not body:
            messagebox.showwarning("Missing Input", "Please provide subject or body content.")
            return

        result = analyze_message(
            Message(
                sender=sender,
                subject=subject,
                body=body,
                message_id="gui-input",
            )
        )
        last_result = result
        verdict_var.set(f"Verdict: {result.verdict}")
        set_badge_from_verdict(result.verdict, result.risk_score)
        output.delete("1.0", "end")
        output.insert("1.0", format_analysis_text(result))

    def load_sample(index: int = 0) -> None:
        sample_pool = sample_messages()
        sample = sample_pool[index % len(sample_pool)]
        sender_entry.delete(0, "end")
        sender_entry.insert(0, sample.sender)
        subject_entry.delete(0, "end")
        subject_entry.insert(0, sample.subject)
        body_text.delete("1.0", "end")
        body_text.insert("1.0", sample.body)

    def clear_all() -> None:
        nonlocal last_result
        last_result = None
        sender_entry.delete(0, "end")
        subject_entry.delete(0, "end")
        body_text.delete("1.0", "end")
        output.delete("1.0", "end")
        verdict_var.set("Verdict: Not analyzed")
        score_var.set("Risk Score: 0/100")
        badge_var.set("Status: Awaiting input")
        verdict_frame.configure(bg="#dce6f5")
        verdict_label.configure(bg="#dce6f5")
        badge_label.configure(bg="#dce6f5", fg="#255f2a")

    def copy_output() -> None:
        text = output.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo("No Output", "Analyze a message first, then copy the result.")
            return
        root.clipboard_clear()
        root.clipboard_append(text)
        messagebox.showinfo("Copied", "Analysis copied to clipboard.")

    def save_result_json() -> None:
        if not last_result:
            messagebox.showinfo("No Result", "Analyze a message first, then save JSON output.")
            return
        file_path = filedialog.asksaveasfilename(
            title="Save Analysis Result",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not file_path:
            return
        Path(file_path).write_text(json.dumps(asdict(last_result), indent=2), encoding="utf-8")
        messagebox.showinfo("Saved", f"Saved analysis to {file_path}")

    def on_analyze_shortcut(_event: tk.Event) -> str:
        analyze_current_input()
        return "break"

    button_frame = tk.Frame(root, padx=12, pady=8)
    button_frame.pack(fill="x")

    tk.Button(button_frame, text="Analyze", command=analyze_current_input, bg="#0b61d8", fg="white").pack(side="left")
    tk.Button(button_frame, text="Load Sample 1", command=lambda: load_sample(0)).pack(side="left", padx=8)
    tk.Button(button_frame, text="Load Sample 2", command=lambda: load_sample(1)).pack(side="left")
    tk.Button(button_frame, text="Clear", command=clear_all).pack(side="left", padx=8)
    tk.Button(button_frame, text="Copy Output", command=copy_output).pack(side="left")
    tk.Button(button_frame, text="Save JSON", command=save_result_json).pack(side="left", padx=8)

    shortcut_label = tk.Label(
        root,
        text="Shortcut: Ctrl+Enter analyzes current input",
        bg="#f2f6fb",
        fg="#53617a",
        padx=12,
        pady=2,
    )
    shortcut_label.pack(anchor="w")

    root.bind_all("<Control-Return>", on_analyze_shortcut)

    print("Desktop GUI running. Close the window to stop.")
    root.mainloop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phishing Awareness Analyzer")
    parser.add_argument(
        "--input",
        type=Path,
        help="Path to message file (.json, .csv, .txt). If omitted, built-in samples are used.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to save JSON report.",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Run the local web interface.",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Run the desktop GUI (Tkinter).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for web mode (default: 8000).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.gui:
        run_desktop_gui()
        return

    if args.web:
        run_web_app(args.port)
        return

    if args.input:
        if not args.input.exists():
            raise FileNotFoundError(f"Input file not found: {args.input}")
        messages = load_messages(args.input)
    else:
        messages = sample_messages()

    results = analyze_messages(messages)
    print_report(results)

    if args.output:
        save_json_report(results, args.output)
        print(f"\nJSON report saved to: {args.output}")


if __name__ == "__main__":
    main()
