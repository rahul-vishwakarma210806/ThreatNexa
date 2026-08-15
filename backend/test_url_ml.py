"""
ThreatNexa - Simple ML URL Test

This script tests the trained URL-only ML model
using a small collection of legitimate-looking
and suspicious-looking URL examples.

IMPORTANT:
The URLs are NOT opened or visited.
They are only passed as text to the ML model.
"""

from services.ml_predictor import predict_url


# ============================================================
# TEST URLS
# ============================================================

legitimate_urls = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.amazon.com",
    "https://www.github.com",
    "https://www.linkedin.com",
    "https://www.python.org",
    "https://www.mozilla.org",
    "https://www.nasa.gov",
]


suspicious_urls = [
    "http://192.168.1.50/login",
    "http://example.com/verify/account/password",
    "http://example.com/login/verify",
    "http://secure-login.example.com/account",
    "http://account-verify.example.com/login",
    "http://example.com/update/password",
    "http://example.com/confirm/account/login",
    "http://example.com/security/verify/password",
    "http://example.com/login?verify=account&password=true",
    "http://example.com/@login/verify",
]


# ============================================================
# TEST FUNCTION
# ============================================================

def test_urls(urls, expected_type):
    print("\n" + "=" * 70)
    print(f"TESTING {expected_type.upper()} URLS")
    print("=" * 70)

    for number, url in enumerate(urls, start=1):

        try:
            result = predict_url(url)

            prediction = result["prediction"]
            phishing_probability = result["phishing_probability"]
            legitimate_probability = result["legitimate_probability"]

            print("\n" + "-" * 70)
            print(f"#{number}")
            print(f"URL: {url}")
            print(f"ML Prediction: {prediction}")
            print(f"Phishing Probability: {phishing_probability}%")
            print(f"Legitimate Probability: {legitimate_probability}%")

        except Exception as e:
            print("\n" + "-" * 70)
            print(f"URL: {url}")
            print(f"ERROR: {e}")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("THREATNEXA ML URL TEST")
    print("=" * 70)

    print("\nTesting 10 legitimate-looking URLs...")
    test_urls(legitimate_urls, "Legitimate")

    print("\nTesting 10 suspicious-looking URLs...")
    test_urls(suspicious_urls, "Suspicious")

    print("\n" + "=" * 70)
    print("ML URL TEST COMPLETE")
    print("=" * 70)