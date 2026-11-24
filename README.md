# Phishing Email Detection and Analysis System

A beginner-friendly, offline Python project that analyzes `.eml` email files for common phishing indicators and creates JSON and HTML reports.

## Features

- Parses sender, recipient, subject, Reply-To and Return-Path headers.
- Checks available SPF, DKIM and DMARC authentication results in the supplied headers.
- Extracts URLs without opening or fetching them.
- Flags HTTP links, URL shorteners, IP-address hosts, punycode and selected uncommon/high-risk TLDs.
- Compares URL-looking visible HTML link text with the actual destination host.
- Looks for common urgency and account-verification phrases.
- Notes attachments by filename and flags selected risky extensions. Attachments are never opened or executed.
- Calculates a transparent heuristic score and generates JSON/HTML reports.
- Includes sample `.eml` files and unit tests.

## Requirements

- Python 3.10 or newer
- Windows, macOS or Linux
- No third-party Python packages required

## Project structure

```text
phishing_email_detection_project/
├── main.py
├── phishing_analyzer.py
├── requirements.txt
├── README.md
├── .gitignore
├── samples/
│   ├── suspicious_sample.eml
│   └── ordinary_sample.eml
└── tests/
    └── test_analyzer.py
```

## Setup

### Windows PowerShell

```powershell
cd phishing_email_detection_project
py -3 --version
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, you can run the commands using `.\.venv\Scripts\python.exe` instead, or use Command Prompt activation:

```cmd
.venv\Scripts\activate.bat
```

### Kali Linux / Ubuntu

```bash
cd phishing_email_detection_project
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Run the project

Analyze the included suspicious sample:

```bash
python main.py samples/suspicious_sample.eml
```

Analyze the ordinary sample:

```bash
python main.py samples/ordinary_sample.eml
```

Choose a report format:

```bash
python main.py samples/suspicious_sample.eml --format json
python main.py samples/suspicious_sample.eml --format html
python main.py samples/suspicious_sample.eml --format both
```

By default, reports are written to the `reports/` folder. This folder is ignored by Git to avoid committing reports containing private email data.

Open the generated HTML report in a browser. Do not click any suspicious URLs shown in the report.

## Run tests

```bash
python -m unittest discover -s tests -v
```

The tests use synthetic sample emails and do not contact the internet.

## How the risk score works

The score is a simple, explainable heuristic, capped at 100. Examples of indicators include:

| Indicator | Example points |
|---|---:|
| Reply-To domain differs from From domain | 20 |
| SPF/DKIM/DMARC reports fail | 15 each |
| URL destination uses an IP address | 12 |
| URL-looking visible text differs from destination host | 15 |
| Known URL shortener | 8 |
| Urgent/phishing phrase | 5–12 |
| Risky attachment extension | 15 |

Verdict bands:

- 0–24: Low indicators detected
- 25–49: Suspicious
- 50–100: Likely phishing

These are demonstration thresholds, not a certified security standard. Multiple weak indicators can add up. A legitimate email may trigger a rule, and a sophisticated phishing email may evade all rules.

## Important limitations

- The tool analyzes `.eml` files, not live inboxes or `.msg` files.
- SPF/DKIM/DMARC results are only assessed if the relevant result headers are present. This tool does not perform DNS checks or cryptographic DKIM verification.
- It does not query VirusTotal or other threat-intelligence services.
- It does not follow redirects, resolve domains, fetch URLs, open attachments or execute content.
- URL and keyword rules are basic indicators and can produce false positives and false negatives.
- The score must not be used as the only basis for an incident decision.

## Safe handling

Use synthetic emails or messages you are authorized to inspect. Do not upload confidential company emails, personal data, attachments or credentials to public services or GitHub. Do not open suspicious links. If investigating a real incident, follow your organization's incident-response process.

## Suggested GitHub description

A Python-based offline phishing email analyzer that parses `.eml` files, checks email-header inconsistencies, extracts and inspects URLs, detects suspicious language, calculates a heuristic risk score, and generates JSON/HTML security reports.

## Future improvements

- Add VirusTotal URL/domain reputation lookup with an optional API key stored in environment variables.
- Add a Streamlit web interface with file upload.
- Add DNS-based SPF/DMARC checks and proper DKIM signature validation.
- Add configurable rules, allowlists and CSV export.
- Add more unit tests and sample email formats.
