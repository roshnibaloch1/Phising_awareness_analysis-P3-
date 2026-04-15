# Cyber Security Project 3 - Phishing Awareness Analysis

This Python project satisfies the Project 3 requirement:

- Analyze sample emails/messages for phishing attempts
- Identify suspicious links and keywords
- List red flags in suspicious messages
- Explain why each unsafe message is risky

## Files

- `phishing_analyzer.py`: Main analyzer and CLI
- `sample_messages.json`: Sample input dataset
- `Cyber Security Project 3.pdf`: Assignment document

## How to run

```powershell
python phishing_analyzer.py
```

Run with custom input (`.json`, `.csv`, or `.txt`):

```powershell
python phishing_analyzer.py --input sample_messages.json
```

Save results to JSON:

```powershell
python phishing_analyzer.py --input sample_messages.json --output report.json
```

Run web interface:

```powershell
python phishing_analyzer.py --web --port 8000
```

Then open: `http://127.0.0.1:8000`

Run desktop GUI:

```powershell
python phishing_analyzer.py --gui
```

GUI usage:

1. Enter sender, subject, and body
2. Click `Analyze` to see phishing verdict and red flags
3. Click `Load Sample 1` or `Load Sample 2` for quick demos
4. Use `Copy Output` to copy the full report text
5. Use `Save JSON` to export the latest analysis result
6. Press `Ctrl+Enter` as a keyboard shortcut to analyze

Run tests:

```powershell
python -m unittest discover -s tests -v
```

GUI-related tests included:

- `test_gui_output_format_contains_key_sections`
- `test_web_form_parser_decodes_encoded_values`

## Input formats

### JSON
Array of objects with fields: `id`, `sender`, `subject`, `body`

### CSV
Headers: `id,sender,subject,body`

### TXT
Use this block format and separate messages with `---`:

```text
Sender: alerts@example.com
Subject: Urgent account verification
Click here now: https://example.top/login

---

Sender: hr@company.com
Subject: Policy update
Please review the attached policy.
```

## Detection logic

The analyzer computes phishing indicators using:

- Suspicious keywords (urgency, credential prompts, payment lures)
- Suspicious URLs (shorteners, risky TLDs, IP-host URLs, punycode)
- Sender/domain mismatch with known brands (impersonation signal)
- Direct credential requests and attachment lures

Each message receives:

- Risk score (0-100)
- Verdict (`LOW RISK`, `SUSPICIOUS`, or `HIGH RISK PHISHING`)
- Extracted links and suspicious-link subset
- Full red-flag list
- Human-readable explanation of why it is unsafe

## Requirement mapping

1. Identify suspicious links/keywords: Report sections `Suspicious Links` and `Suspicious Keywords`
2. List red flags: Report section `Red Flags`
3. Explain why unsafe: Report section `Why Unsafe`

## Notes

This is a rule-based awareness project for educational use. For production filtering, combine these checks with advanced ML models, URL reputation feeds, and sandboxing.
