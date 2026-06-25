from analyzers.text_classifier import PhishingTextClassifier


def main():
    classifier = PhishingTextClassifier()

    test_email = """
    Subject: Account Verification Required

    Dear user,

    Your account security needs immediate attention.
    Please verify your credentials to avoid account suspension.

    Click here: http://suspicious-login-example.com

    Thank you,
    Security Team
    """

    result = classifier.predict(test_email)

    print("\n=== Text Classifier Result ===")
    print(f"Classification: {result['classification']}")
    print(f"Phishing Score: {result['phishing_score']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Raw Prediction: {result['raw_prediction']}")
    print("\nAll Probabilities:")

    for label, score in result["all_probabilities"].items():
        print(f"  {label}: {score}")


if __name__ == "__main__":
    main()