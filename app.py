from pathlib import Path

from utils.email_parser import EmailParser

from analyzers.text_classifier import PhishingTextClassifier
from analyzers.header_analyzer import PhishingHeaderAnalyzer
from analyzers.url_analyzer import PhishingURLAnalyzer
from analyzers.attachment_analyzer import PhishingAttachmentAnalyzer
from analyzers.social_engineering_analyzer import SocialEngineeringAnalyzer

from scoring.risk_engine import PhishingRiskEngine


BASE_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = BASE_DIR / "samples"


def main():
    selected_file = choose_sample_file()

    raw_email = read_email_file(selected_file)

    parser = EmailParser()
    parsed_email = parser.parse(raw_email)

    print("\n=== SELECTED SAMPLE ===")
    print(f"File: {selected_file.name}")

    print("\n=== PARSED EMAIL ===")
    print(f"Subject: {parsed_email['subject']}")
    print(f"Attachments: {parsed_email['attachment_names']}")
    print(f"Body preview: {parsed_email['body'][:200]}")

    # Initialize analyzers after file selection.
    text_classifier = PhishingTextClassifier()
    header_analyzer = PhishingHeaderAnalyzer()
    url_analyzer = PhishingURLAnalyzer()
    attachment_analyzer = PhishingAttachmentAnalyzer()
    social_analyzer = SocialEngineeringAnalyzer()
    risk_engine = PhishingRiskEngine()

    # Run individual modules.
    text_result = text_classifier.predict(parsed_email["analysis_text"])
    header_result = header_analyzer.analyze(parsed_email["raw_email"])
    url_result = url_analyzer.analyze(parsed_email["analysis_text"])

    # If MIME attachments exist, use those. Otherwise, safely scan only the body.
    if parsed_email["attachment_names"]:
        attachment_result = attachment_analyzer.analyze(parsed_email["attachment_names"])
    else:
        attachment_result = attachment_analyzer.analyze(parsed_email["body"])

    social_result = social_analyzer.analyze(parsed_email["analysis_text"])

    # Combine everything.
    final_result = risk_engine.calculate_final_risk(
        text_result=text_result,
        header_result=header_result,
        url_result=url_result,
        attachment_result=attachment_result,
        social_result=social_result
    )

    print_final_result(final_result)


def choose_sample_file() -> Path:
    sample_files = list_sample_files()

    if not sample_files:
        print("\nNo .txt sample files found.")
        print(f"Expected folder: {SAMPLES_DIR}")
        raise SystemExit(1)

    print("\n=== AVAILABLE EMAIL SAMPLES ===")

    for index, file_path in enumerate(sample_files, start=1):
        print(f"{index}. {file_path.name}")

    while True:
        user_input = input("\nEnter the number of the email sample to analyze: ").strip()

        if not user_input:
            print("Input cannot be empty. Please enter a number.")
            continue

        if not user_input.isdigit():
            print("Invalid input. Please enter a valid number.")
            continue

        selected_index = int(user_input)

        if selected_index < 1 or selected_index > len(sample_files):
            print(f"Invalid number. Please enter a number between 1 and {len(sample_files)}.")
            continue

        return sample_files[selected_index - 1]


def list_sample_files():
    if not SAMPLES_DIR.exists():
        print(f"\nSamples folder does not exist: {SAMPLES_DIR}")
        return []

    if not SAMPLES_DIR.is_dir():
        print(f"\nSamples path exists but is not a folder: {SAMPLES_DIR}")
        return []

    return sorted(SAMPLES_DIR.glob("*.txt"))


def read_email_file(path: Path) -> str:
    try:
        with open(path, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        print(f"\nSelected file was not found: {path}")
        raise SystemExit(1)
    except UnicodeDecodeError:
        print(f"\nCould not read file as UTF-8 text: {path}")
        raise SystemExit(1)


def print_final_result(result):
    print("\n=== FINAL RISK RESULT ===")
    print(f"Final Classification: {result['final_classification']}")
    print(f"Overall Score: {result['overall_score']}/{result['max_score']}")
    print(f"Overall Score Classification: {result['overall_score_classification']}")
    print(f"Component Override Applied: {result['component_override_applied']}")

    high_risk_detected = result.get(
        "high_risk_component_detected",
        bool(result.get("high_risk_components"))
    )

    suspicious_detected = result.get(
        "suspicious_component_detected",
        bool(result.get("suspicious_components"))
    )

    print(f"High-Risk Component Detected: {high_risk_detected}")
    print(f"Suspicious Component Detected: {suspicious_detected}")

    if result.get("component_override_reason"):
        print(f"Component Override Reason: {result['component_override_reason']}")

    print("\nExplanation:")
    for item in result["explanation"]:
        print(f"  - {item}")

    print("\nComponent Results:")
    for component_name, component in result["components"].items():
        print(f"  {component['display_name']}:")
        print(f"    Score: {component['score']}/{component['max_score']}")
        print(f"    Risk Percentage: {component['risk_percentage']}%")
        print(f"    Component Classification: {component['component_classification']}")
        print(f"    Raw Classification: {component['raw_classification']}")

    print("\nMITRE Mapping:")
    if not result["mitre_mapping"]:
        print("  None")
    else:
        for technique in result["mitre_mapping"]:
            print(f"  - {technique}")

    print("\nFindings:")
    if not result["findings"]:
        print("  No findings.")
    else:
        for finding in result["findings"]:
            print(f"  - [{finding['severity']}] {finding['finding']}")
            print(f"    Component: {finding['component_display_name']}")

            if "explanation" in finding:
                print(f"    {finding['explanation']}")

            if "url" in finding:
                print(f"    URL: {finding['url']}")

            if "filename" in finding:
                print(f"    File: {finding['filename']}")

            if "evidence" in finding:
                print(f"    Evidence: {', '.join(finding['evidence'])}")

            if "mitre_mapping" in finding:
                print(f"    MITRE: {', '.join(finding['mitre_mapping'])}")


if __name__ == "__main__":
    main()