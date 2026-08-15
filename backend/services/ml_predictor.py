import os
import joblib


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "models",
    "url_phishing_model.pkl"
)

VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "models",
    "url_vectorizer.pkl"
)


# ============================================================
# LOAD MODEL AND VECTORIZER
# ============================================================

print("Loading ThreatNexa URL ML model...")

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

print("ThreatNexa URL ML model loaded successfully!")


# ============================================================
# PREDICT URL
# ============================================================

def predict_url(url: str):
    """
    Predict whether a URL is phishing or legitimate.

    Returns:
        prediction
        phishing probability
        legitimate probability
    """

    # Convert URL into the same features used during training
    url_vector = vectorizer.transform([url])

    # Get prediction
    prediction = model.predict(url_vector)[0]

    # Get probabilities
    probabilities = model.predict_proba(url_vector)[0]

    # Dataset labels:
    # 0 = Phishing
    # 1 = Legitimate

    phishing_probability = probabilities[0] * 100
    legitimate_probability = probabilities[1] * 100

    if prediction == 0:
        result = "PHISHING"
    else:
        result = "LEGITIMATE"

    return {
        "prediction": result,
        "phishing_probability": float(round(
            phishing_probability, 2
        )),
        "legitimate_probability": float(round(
            legitimate_probability, 2
        ))
    }