import pandas as pd
from pathlib import Path


dataset_path = (
    Path(__file__).parent.parent
    / "dataset"
    / "PhiUSIIL_Phishing_URL_Dataset.csv"
)


print("=" * 60)
print("ThreatNexa Dataset Inspection")
print("=" * 60)

print("\nLoading dataset...")

df = pd.read_csv(dataset_path)

print("Dataset loaded successfully!")


print("\n===== DATASET SHAPE =====")
print(f"Rows    : {df.shape[0]:,}")
print(f"Columns : {df.shape[1]}")


print("\n===== COLUMNS =====")

for i, column in enumerate(df.columns, start=1):
    print(f"{i:02d}. {column}")


print("\n===== LABEL DISTRIBUTION =====")

if "label" in df.columns:
    print(df["label"].value_counts())
elif "Label" in df.columns:
    print(df["Label"].value_counts())
else:
    print("Label column not found.")


print("\n===== MISSING VALUES =====")

missing = df.isnull().sum()

if missing.sum() == 0:
    print("No missing values found.")
else:
    print(missing[missing > 0])


print("\n===== DUPLICATES =====")
print(f"Duplicate rows: {df.duplicated().sum():,}")


print("\n===== FIRST 5 ROWS =====")
print(df.head().to_string())


print("\n" + "=" * 60)
print("Inspection complete.")
print("=" * 60)