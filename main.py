import argparse
from pathlib import Path
from phishing_analyzer import analyze_email, save_html, save_json

def main():
    parser = argparse.ArgumentParser(description="Offline phishing email analyzer (.eml)")
    parser.add_argument("email_file", help="Path to an .eml email file")
    parser.add_argument("--format", choices=["json", "html", "both"], default="both")
    parser.add_argument("--output-dir", default="reports", help="Directory for generated reports")
    args = parser.parse_args()

    email_path = Path(args.email_file)
    if not email_path.is_file():
        parser.error(f"File not found: {email_path}")
    if email_path.suffix.lower() != ".eml":
        parser.error("Please provide an .eml file.")

    report = analyze_email(email_path)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = email_path.stem

    print("\n========== PHISHING EMAIL ANALYSIS ==========")
    print(f"File       : {report['file_name']}")
    print(f"Subject    : {report['subject']}")
    print(f"From       : {report['from']}")
    print(f"Risk score : {report['risk_score']}/100")
    print(f"Verdict    : {report['verdict']}")
    print("\nFindings:")
    if report["findings"]:
        for finding in report["findings"]:
            print(f"- [{finding['severity'].upper()}] {finding['detail']}")
    else:
        print("- No indicators triggered.")
    print("\nURLs:")
    for item in report["urls"]:
        print(f"- {item['url']} | {', '.join(item['indicators']) or 'No URL rule triggered'}")

    if args.format in ("json", "both"):
        path = output_dir / f"{stem}_report.json"
        save_json(report, path)
        print(f"\nJSON report: {path}")
    if args.format in ("html", "both"):
        path = output_dir / f"{stem}_report.html"
        save_html(report, path)
        print(f"HTML report: {path}")
    print("\nSafety: URLs are analyzed as text only; they are never opened or fetched.")

if __name__ == "__main__":
    main()
