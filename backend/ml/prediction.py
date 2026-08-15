import os
import joblib
import pandas as pd


# ============================================================
# MODEL PATH
# ============================================================

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "models",
    "phishing_model.pkl"
)


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

model = joblib.load(MODEL_PATH)


# ============================================================
# EXACT FEATURES USED DURING TRAINING
# ============================================================

FEATURE_COLUMNS = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "URLSimilarityIndex",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
    "HasTitle",
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "HasFavicon",
    "Robots",
    "IsResponsive",
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasDescription",
    "NoOfPopup",
    "NoOfiFrame",
    "HasExternalFormSubmit",
    "HasSocialNet",
    "HasSubmitButton",
    "HasHiddenFields",
    "HasPasswordField",
    "Bank",
    "Pay",
    "Crypto",
    "HasCopyrightInfo",
    "NoOfImage",
    "NoOfCSS",
    "NoOfJS",
    "NoOfSelfRef",
    "NoOfEmptyRef",
    "NoOfExternalRef",
]


# ============================================================
# CONVERT URL FEATURES TO ML FEATURES
# ============================================================

def build_ml_features(features: dict):
    """
    Convert the features extracted by ThreatNexa's
    URL analyzer into the 48 features expected
    by the trained Random Forest model.

    Some PhiUSIIL features require webpage information.
    Since we are currently analyzing only the URL,
    those webpage-specific values are set to 0.
    """

    url = features["url"]
    hostname = features["hostname"]

    # Basic calculations
    url_length = features["url_length"]

    domain_length = len(hostname)

    digit_count = sum(
        character.isdigit()
        for character in url
    )

    letter_count = sum(
        character.isalpha()
        for character in url
    )

    special_count = features["special_character_count"]

    total_characters = max(len(url), 1)

    # Query-related values
    query = ""

    if "?" in url:
        query = url.split("?", 1)[1]

    equals_count = url.count("=")
    question_count = url.count("?")
    ampersand_count = url.count("&")

    # URL encoding
    encoded_count = url.count("%")

    # TLD
    tld = ""

    if "." in hostname:
        tld = hostname.split(".")[-1]

    # ========================================================
    # BUILD FEATURE DICTIONARY
    # ========================================================

    ml_features = {

        "URLLength":
            url_length,

        "DomainLength":
            domain_length,

        "IsDomainIP":
            int(features["has_ip_address"]),

        # Not currently calculated by our URL analyzer
        "URLSimilarityIndex":
            0,

        "CharContinuationRate":
            0,

        "TLDLegitimateProb":
            0,

        "URLCharProb":
            0,

        "TLDLength":
            len(tld),

        "NoOfSubDomain":
            features["subdomain_count"],

        "HasObfuscation":
            int(features["has_url_encoding"]),

        "NoOfObfuscatedChar":
            encoded_count,

        "ObfuscationRatio":
            encoded_count / total_characters,

        "NoOfLettersInURL":
            letter_count,

        "LetterRatioInURL":
            letter_count / total_characters,

        "NoOfDegitsInURL":
            digit_count,

        "DegitRatioInURL":
            digit_count / total_characters,

        "NoOfEqualsInURL":
            equals_count,

        "NoOfQMarkInURL":
            question_count,

        "NoOfAmpersandInURL":
            ampersand_count,

        "NoOfOtherSpecialCharsInURL":
            special_count,

        "SpacialCharRatioInURL":
            special_count / total_characters,

        "IsHTTPS":
            int(features["uses_https"]),

        # ----------------------------------------------------
        # Webpage-level features
        # ----------------------------------------------------
        # These require downloading/analyzing the actual
        # webpage. We will implement those later.
        # ----------------------------------------------------

        "HasTitle":
            0,

        "DomainTitleMatchScore":
            0,

        "URLTitleMatchScore":
            0,

        "HasFavicon":
            0,

        "Robots":
            0,

        "IsResponsive":
            0,

        "NoOfURLRedirect":
            0,

        "NoOfSelfRedirect":
            0,

        "HasDescription":
            0,

        "NoOfPopup":
            0,

        "NoOfiFrame":
            0,

        "HasExternalFormSubmit":
            0,

        "HasSocialNet":
            0,

        "HasSubmitButton":
            0,

        "HasHiddenFields":
            0,

        "HasPasswordField":
            0,

        "Bank":
            0,

        "Pay":
            0,

        "Crypto":
            0,

        "HasCopyrightInfo":
            0,

        "NoOfImage":
            0,

        "NoOfCSS":
            0,

        "NoOfJS":
            0,

        "NoOfSelfRef":
            0,

        "NoOfEmptyRef":
            0,

        "NoOfExternalRef":
            0,
    }

    # Make absolutely sure all required columns exist
    for column in FEATURE_COLUMNS:
        if column not in ml_features:
            ml_features[column] = 0

    # Return DataFrame in EXACT training order
    return pd.DataFrame(
        [[ml_features[column] for column in FEATURE_COLUMNS]],
        columns=FEATURE_COLUMNS
    )


# ============================================================
# PREDICT
# ============================================================

def predict_url(features: dict):
    """
    Predict whether a URL is phishing or legitimate.
    """

    ml_input = build_ml_features(features)

    prediction = model.predict(ml_input)[0]

    probabilities = model.predict_proba(ml_input)[0]

    # Classes are [0, 1]
    phishing_probability = probabilities[0]
    legitimate_probability = probabilities[1]

    if prediction == 0:
        prediction_label = "PHISHING"
    else:
        prediction_label = "LEGITIMATE"

    return {
        "prediction": int(prediction),
        "prediction_label": prediction_label,
        "phishing_probability": round(
            float(phishing_probability) * 100,
            2
        ),
        "legitimate_probability": round(
            float(legitimate_probability) * 100,
            2
        ),
    }