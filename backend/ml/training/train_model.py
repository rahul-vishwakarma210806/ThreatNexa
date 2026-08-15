import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


# ============================================================
# PATHS
# ============================================================

DATASET_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "dataset",
    "PhiUSIIL_Phishing_URL_Dataset.csv"
)

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "models",
    "phishing_model.pkl"
)


# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 60)
print("ThreatNexa ML Training")
print("=" * 60)

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

print("Dataset loaded successfully!")
print(f"Rows    : {len(df):,}")
print(f"Columns : {len(df)}")


# ============================================================
# SELECT FEATURES
# ============================================================

features = [
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
# PREPARE X AND Y
# ============================================================

X = df[features]
y = df["label"]

print("\n===== TRAINING DATA =====")
print(f"Features : {len(features)}")
print(f"Samples  : {len(X):,}")

print("\n===== LABEL DISTRIBUTION =====")
print(y.value_counts())


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\n===== DATA SPLIT =====")
print(f"Training samples : {len(X_train):,}")
print(f"Testing samples  : {len(X_test):,}")


# ============================================================
# CREATE MODEL
# ============================================================

print("\nCreating Random Forest model...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)


# ============================================================
# TRAIN
# ============================================================

print("Training model...")
print("This may take some time...\n")

model.fit(X_train, y_train)

print("Training completed!")


# ============================================================
# EVALUATE
# ============================================================

print("\n===== MODEL EVALUATION =====")

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print(f"\nAccuracy: {accuracy * 100:.2f}%")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Phishing",
            "Legitimate"
        ]
    )
)


# ============================================================
# SAVE MODEL
# ============================================================

os.makedirs(
    os.path.dirname(MODEL_PATH),
    exist_ok=True
)

joblib.dump(model, MODEL_PATH)

print("\n===== MODEL SAVED =====")
print(f"Model path:")
print(os.path.abspath(MODEL_PATH))

print("\n" + "=" * 60)
print("Training complete!")
print("=" * 60)