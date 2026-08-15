import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATASET_PATH = os.path.join(
    BASE_DIR,
    "dataset",
    "PhiUSIIL_Phishing_URL_Dataset.csv"
)
MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "url_phishing_model.pkl"
)

VECTORIZER_PATH = os.path.join(
    MODEL_DIR,
    "url_vectorizer.pkl"
)


# ============================================================
# START
# ============================================================

print("=" * 60)
print("ThreatNexa URL-Only ML Training")
print("=" * 60)

print("\nLoading dataset...")
print(f"Dataset path: {DATASET_PATH}")


# ============================================================
# CHECK DATASET
# ============================================================

if not os.path.exists(DATASET_PATH):
    print("\nERROR: Dataset not found!")
    print(DATASET_PATH)
    raise SystemExit(1)


# ============================================================
# LOAD DATASET
# ============================================================

df = pd.read_csv(DATASET_PATH)

print("\nDataset loaded successfully!")

print(f"Rows    : {len(df):,}")
print(f"Columns : {len(df)}")


# ============================================================
# CHECK REQUIRED COLUMNS
# ============================================================

if "URL" not in df.columns:
    print("\nERROR: URL column not found!")
    print("Available columns:")
    print(df.columns.tolist())
    raise SystemExit(1)

if "label" not in df.columns:
    print("\nERROR: label column not found!")
    print("Available columns:")
    print(df.columns.tolist())
    raise SystemExit(1)


# ============================================================
# PREPARE DATA
# ============================================================

print("\nPreparing URL data...")

X = df["URL"].astype(str)
y = df["label"].astype(int)


print("\n===== LABEL DISTRIBUTION =====")
print(y.value_counts())

print("\nLabel meaning:")
print("0 = Phishing")
print("1 = Legitimate")


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
# TF-IDF VECTORIZER
# ============================================================

print("\nCreating URL vectorizer...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(2, 5),
    min_df=2,
    max_features=100000,
    sublinear_tf=True
)


# ============================================================
# TRANSFORM URLS
# ============================================================

print("Converting URLs into ML features...")

X_train_vectorized = vectorizer.fit_transform(X_train)

X_test_vectorized = vectorizer.transform(X_test)

print("URL vectorization completed!")

print(
    f"Number of URL features: "
    f"{X_train_vectorized.shape[1]:,}"
)


# ============================================================
# CREATE MODEL
# ============================================================

print("\nCreating Logistic Regression model...")

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    random_state=42
)


# ============================================================
# TRAIN MODEL
# ============================================================

print("Training model...")
print("This may take some time...\n")

model.fit(
    X_train_vectorized,
    y_train
)

print("Training completed!")


# ============================================================
# EVALUATION
# ============================================================

print("\n===== MODEL EVALUATION =====")

y_pred = model.predict(X_test_vectorized)

accuracy = accuracy_score(
    y_test,
    y_pred
)

print(
    f"\nAccuracy: "
    f"{accuracy * 100:.2f}%"
)

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
    MODEL_DIR,
    exist_ok=True
)

joblib.dump(
    model,
    MODEL_PATH
)

joblib.dump(
    vectorizer,
    VECTORIZER_PATH
)


# ============================================================
# SUCCESS
# ============================================================

print("\n===== MODEL SAVED =====")

print("Model:")
print(
    os.path.abspath(MODEL_PATH)
)

print("\nVectorizer:")
print(
    os.path.abspath(VECTORIZER_PATH)
)

print("\n" + "=" * 60)
print("URL-Only ML Training complete!")
print("=" * 60)