from services.url_analyzer import extract_url_features
from services.risk_engine import calculate_risk


test_url = "https://example.com/login?user=123"

features = extract_url_features(test_url)

risk_result = calculate_risk(features)

print("\n===== URL FEATURES =====")

for key, value in features.items():
    print(f"{key}: {value}")


print("\n===== RISK ANALYSIS =====")

print(f"Risk Score: {risk_result['risk_score']}/100")
print(f"Risk Level: {risk_result['risk_level']}")

print("\nReasons:")

for reason in risk_result["reasons"]:
    print(f"- {reason}")

print("\nPositive Signals:")

for signal in risk_result["positive_signals"]:
    print(f"- {signal}")