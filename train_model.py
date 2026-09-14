import pandas as pd
import numpy as np
import pickle

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

# ============================================================
# 1. KDD COLUMN NAMES
# ============================================================

columns = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "label"
]

# ============================================================
# 2. LOAD DATASET
# ============================================================

print("\n========================================")
print("AI CYBERSECURITY THREAT DETECTION")
print("========================================")

print("\nLoading dataset...")

df = pd.read_csv(
    "dataset.csv",
    names=columns,
    header=None
)

print("Dataset loaded successfully!")
print("Total records:", len(df))

# ============================================================
# 3. CLEAN DATA
# ============================================================

print("\nCleaning dataset...")

# Remove whitespace
df["label"] = df["label"].astype(str).str.strip()

# Remove trailing '.' from KDD labels
df["label"] = df["label"].str.replace(".", "", regex=False)

# Remove missing values
df = df.dropna()

print("Records after cleaning:", len(df))

# ============================================================
# 4. CONVERT MULTI-CLASS LABEL TO BINARY
# ============================================================

# normal = 0
# anything else = 1

df["target"] = np.where(
    df["label"].str.lower() == "normal",
    0,
    1
)

print("\nTarget distribution:")
print(df["target"].value_counts())

# ============================================================
# 5. FEATURES AND TARGET
# ============================================================

X = df.drop(["label", "target"], axis=1)
y = df["target"]

categorical_columns = [
    "protocol_type",
    "service",
    "flag"
]

numeric_columns = [
    col for col in X.columns
    if col not in categorical_columns
]

print("\nCategorical columns:")
print(categorical_columns)

print("\nNumeric columns:")
print(len(numeric_columns))

# ============================================================
# 6. PREPROCESSING
# ============================================================

preprocessor = ColumnTransformer(
    transformers=[
        (
            "categorical",
            OneHotEncoder(
                handle_unknown="ignore"
            ),
            categorical_columns
        ),
        (
            "numeric",
            "passthrough",
            numeric_columns
        )
    ]
)

# ============================================================
# 7. RANDOM FOREST MODEL
# ============================================================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

# Complete ML pipeline
pipeline = Pipeline(
    steps=[
        ("preprocessing", preprocessor),
        ("model", model)
    ]
)

# ============================================================
# 8. TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining records:", len(X_train))
print("Testing records:", len(X_test))

# ============================================================
# 9. TRAIN MODEL
# ============================================================

print("\nTraining Random Forest model...")

pipeline.fit(X_train, y_train)

print("Training completed!")

# ============================================================
# 10. PREDICTION
# ============================================================

print("\nGenerating predictions...")

predictions = pipeline.predict(X_test)

# ============================================================
# 11. MODEL EVALUATION
# ============================================================

accuracy = accuracy_score(y_test, predictions)
precision = precision_score(y_test, predictions, zero_division=0)
recall = recall_score(y_test, predictions, zero_division=0)
f1 = f1_score(y_test, predictions, zero_division=0)

print("\n========================================")
print("MODEL PERFORMANCE")
print("========================================")

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=["Normal", "Attack"],
        zero_division=0
    )
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))

# ============================================================
# 12. SAVE COMPLETE PIPELINE
# ============================================================

print("\nSaving complete ML pipeline...")

with open("model.pkl", "wb") as file:
    pickle.dump(pipeline, file)

print("\n========================================")
print("MODEL SAVED SUCCESSFULLY!")
print("File: model.pkl")
print("========================================")