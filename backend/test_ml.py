from services.url_analyzer import extract_url_features
from ml.prediction import predict_url


test_urls = [
    "https://example.com",
    "https://example.com/login",
    "http://192.168.1.50/login",
    "https://bit.ly/example",
]


print("=" * 60)
print("ThreatNexa ML MODEL TEST")
print("=" * 60)


for url in test_urls:

    print("\n" + "-" * 60)
    print("URL:", url)

    features = extract_url_features(url)

    result = predict_url(features)

    print("Prediction:", result["prediction_label"])
    print(
        "Phishing probability:",
        result["phishing_probability"],
        "%"
    )
    print(
        "Legitimate probability:",
        result["legitimate_probability"],
        "%"
    )