"""Safe, offline phishing email analyzer. Never fetches URLs or executes attachments."""
from __future__ import annotations

import hashlib
import html
import json
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"']+""")
IP_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
SUSPICIOUS_TLDS = {".zip", ".mov", ".top", ".xyz", ".click", ".work", ".country", ".gq", ".tk"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
PHISHING_TERMS = {
    "verify your account": 12, "account suspended": 12, "urgent action": 10,
    "password expires": 10, "confirm your identity": 10, "unusual activity": 8,
    "update your payment": 10, "wire transfer": 8, "gift card": 8,
    "click here": 5, "login immediately": 10, "reset your password": 6,
    "final warning": 10, "limited time": 5,
}

class LinkTextParser(HTMLParser):
    """Collect visible anchor text and href values without loading remote content."""
    def __init__(self):
        super().__init__()
        self.links: list[dict[str, str]] = []
        self._current: dict[str, str] | None = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href", "")
            self._current = {"href": href, "text": ""}

    def handle_data(self, data):
        if self._current is not None:
            self._current["text"] += data

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current is not None:
            self.links.append(self._current)
            self._current = None


def _domain(address: str) -> str:
    match = re.search(r"@([A-Za-z0-9.-]+)", address or "")
    return match.group(1).lower().strip(".") if match else ""


def _normalize_url(raw: str) -> str:
    raw = raw.rstrip(".,;:!?)]}")
    if raw.lower().startswith("www."):
        return "http://" + raw
    return raw


def _extract_message_content(message) -> tuple[str, str, list[str]]:
    text_parts, html_parts, attachments = [], [], []
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            if filename:
                attachments.append(filename)
            continue
        content_type = part.get_content_type()
        try:
            content = part.get_content()
            if isinstance(content, bytes):
                content = content.decode(part.get_content_charset() or "utf-8", errors="replace")
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if content_type == "text/plain":
            text_parts.append(str(content))
        elif content_type == "text/html":
            html_parts.append(str(content))
    return "\n".join(text_parts), "\n".join(html_parts), attachments


def analyze_email(file_path: str | Path) -> dict[str, Any]:
    """Analyze an .eml file and return a JSON-serializable report."""
    path = Path(file_path)
    raw = path.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw)

    sender = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))
    return_path = str(message.get("Return-Path", ""))
    subject = str(message.get("Subject", ""))
    recipient = str(message.get("To", ""))
    auth_results = str(message.get("Authentication-Results", ""))
    received_spf = str(message.get("Received-SPF", ""))
    plain, html_body, attachments = _extract_message_content(message)
    body = plain + "\n" + html_body
    lower_body = body.lower()

    findings: list[dict[str, Any]] = []
    score = 0

    def add(category: str, severity: str, points: int, detail: str):
        nonlocal score
        findings.append({"category": category, "severity": severity, "points": points, "detail": detail})
        score += points

    sender_domain = _domain(sender)
    reply_domain = _domain(reply_to)
    return_domain = _domain(return_path)

    if reply_to and sender_domain and reply_domain and sender_domain != reply_domain:
        add("Email header", "high", 20, f"Reply-To domain ({reply_domain}) differs from From domain ({sender_domain}).")
    if return_domain and sender_domain and return_domain != sender_domain:
        add("Email header", "medium", 10, f"Return-Path domain ({return_domain}) differs from From domain ({sender_domain}).")

    auth_text = (auth_results + " " + received_spf).lower()
    for mechanism in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{mechanism}\s*=\s*fail\b|\b{mechanism}\s+fail\b", auth_text):
            add("Authentication", "high", 15, f"{mechanism.upper()} authentication reports FAIL.")
        elif re.search(rf"\b{mechanism}\s*=\s*pass\b|\b{mechanism}\s+pass\b", auth_text):
            findings.append({"category": "Authentication", "severity": "info", "points": 0,
                             "detail": f"{mechanism.upper()} authentication reports PASS."})

    urls = []
    for raw_url in URL_RE.findall(body):
        url = _normalize_url(raw_url)
        if url not in urls:
            urls.append(url)

    html_parser = LinkTextParser()
    if html_body:
        try:
            html_parser.feed(html_body)
        except Exception:
            pass

    analyzed_urls = []
    for url in urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        url_findings = []
        if parsed.scheme == "http":
            url_findings.append("Uses unencrypted HTTP")
            add("URL", "medium", 5, f"Link uses HTTP rather than HTTPS: {url}")
        if host in SHORTENERS:
            url_findings.append("URL shortener")
            add("URL", "medium", 8, f"URL uses a known shortening service: {host}")
        if host and IP_HOST_RE.match(host):
            url_findings.append("IP address used as host")
            add("URL", "high", 12, f"URL uses an IP address instead of a domain: {url}")
        if host.startswith("xn--") or ".xn--" in host:
            url_findings.append("Punycode domain")
            add("URL", "medium", 8, f"URL contains a punycode hostname: {host}")
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            url_findings.append("Uncommon/high-risk TLD")
            add("URL", "low", 4, f"URL uses a TLD that deserves extra scrutiny: {host}")
        analyzed_urls.append({"url": url, "host": host, "indicators": url_findings})

    # Compare displayed anchor text with destination host when the text looks like a URL.
    for link in html_parser.links:
        displayed = link["text"].strip()
        href = _normalize_url(link["href"].strip()) if link["href"].strip() else ""
        if not href or not displayed:
            continue
        if re.match(r"(?i)^(https?://|www\.)", displayed):
            display_host = (urlparse(_normalize_url(displayed)).hostname or "").lower()
            destination_host = (urlparse(href).hostname or "").lower()
            if display_host and destination_host and display_host != destination_host:
                add("URL mismatch", "high", 15,
                    f"Displayed link host ({display_host}) differs from destination host ({destination_host}).")

    matched_terms = []
    for term, points in PHISHING_TERMS.items():
        if term in lower_body or term in subject.lower():
            matched_terms.append(term)
            add("Language", "medium", points, f"Urgent or commonly abused phishing phrase detected: '{term}'.")

    if attachments:
        add("Attachment", "medium", 5, f"Email contains {len(attachments)} attachment(s); inspect safely in an isolated environment.")
    for name in attachments:
        if Path(name).suffix.lower() in {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".iso", ".img"}:
            add("Attachment", "high", 15, f"Potentially risky attachment extension: {Path(name).suffix}")

    score = min(score, 100)
    if score >= 50:
        verdict = "Likely phishing"
    elif score >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Low indicators detected"

    recommendations = []
    if verdict != "Low indicators detected":
        recommendations.extend([
            "Do not click links or open attachments from this message.",
            "Verify the request with the sender using a known, independent contact method.",
            "Report the message to your organization's security or IT team."
        ])
    else:
        recommendations.extend([
            "No strong phishing indicators were detected by these basic rules.",
            "This result does not prove the email is safe; verify unexpected requests independently."
        ])
    if not auth_text:
        recommendations.append("Authentication results were not present in the supplied email; SPF/DKIM/DMARC could not be assessed.")

    return {
        "file_name": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "subject": subject,
        "from": sender,
        "to": recipient,
        "reply_to": reply_to,
        "return_path": return_path,
        "risk_score": score,
        "verdict": verdict,
        "findings": findings,
        "urls": analyzed_urls,
        "matched_phishing_terms": matched_terms,
        "attachment_names": attachments,
        "recommendations": recommendations,
        "disclaimer": "Heuristic result only. A low score does not guarantee an email is safe; validate findings manually."
    }


def save_json(report: dict[str, Any], output_path: str | Path) -> None:
    Path(output_path).write_text(json.dumps(report, indent=2), encoding="utf-8")


def save_html(report: dict[str, Any], output_path: str | Path) -> None:
    esc = lambda value: html.escape(str(value))
    findings_rows = "".join(
        f"<tr><td>{esc(f['category'])}</td><td>{esc(f['severity'])}</td><td>{f['points']}</td><td>{esc(f['detail'])}</td></tr>"
        for f in report["findings"]
    ) or "<tr><td colspan='4'>No indicators found.</td></tr>"
    url_rows = "".join(
        f"<tr><td>{esc(u['url'])}</td><td>{esc(u['host'])}</td><td>{esc(', '.join(u['indicators']) or 'No URL rule triggered')}</td></tr>"
        for u in report["urls"]
    ) or "<tr><td colspan='3'>No URLs found.</td></tr>"
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phishing Analysis Report</title><style>
body{{font:16px Arial,sans-serif;max-width:1000px;margin:35px auto;padding:0 18px;color:#202733;background:#f5f7fa}}
header,.panel{{background:white;padding:22px;border-radius:12px;margin:14px 0;box-shadow:0 2px 10px #0000000d}}
h1{{margin-top:0}}.score{{font-size:30px;font-weight:bold}}table{{width:100%;border-collapse:collapse;overflow-wrap:anywhere}}
th,td{{padding:10px;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top}}th{{background:#eef2f7}}
small{{color:#596579}}li{{margin:8px 0}}
</style></head><body><header><h1>Phishing Email Analysis</h1>
<p><b>Verdict:</b> {esc(report['verdict'])}</p><p class="score">Risk score: {report['risk_score']}/100</p>
<p><b>File:</b> {esc(report['file_name'])}<br><b>SHA-256:</b> {esc(report['sha256'])}</p></header>
<section class="panel"><h2>Email details</h2><p><b>Subject:</b> {esc(report['subject'])}<br><b>From:</b> {esc(report['from'])}<br><b>To:</b> {esc(report['to'])}<br><b>Reply-To:</b> {esc(report['reply_to'])}<br><b>Return-Path:</b> {esc(report['return_path'])}</p></section>
<section class="panel"><h2>Findings</h2><table><tr><th>Category</th><th>Severity</th><th>Points</th><th>Details</th></tr>{findings_rows}</table></section>
<section class="panel"><h2>URLs</h2><table><tr><th>URL</th><th>Host</th><th>Indicators</th></tr>{url_rows}</table></section>
<section class="panel"><h2>Recommended actions</h2><ul>{''.join('<li>'+esc(x)+'</li>' for x in report['recommendations'])}</ul>
<p><small>{esc(report['disclaimer'])}</small></p></section></body></html>"""
    Path(output_path).write_text(doc, encoding="utf-8")
