import pandas as pd
import pickle

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score


# ==========================================
# Load Sequence-Aware Dataset
# ==========================================

DATASET = "datasets/sequence_security_logs.csv"

data = pd.read_csv(DATASET)

X = data["log"].fillna("")
y = data["label"]


# ==========================================
# Show Dataset Information
# ==========================================

print("\n==========================================")
print("Training Enhanced AI Threat Model")
print("==========================================")

print(f"Total samples: {len(data)}")

print("\nClass distribution:")
print(y.value_counts())


# ==========================================
# Train / Test Split
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# ==========================================
# AI Pipeline
# ==========================================

model = Pipeline([

    (
        "vectorizer",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=1,
            sublinear_tf=True
        )
    ),

    (
        "classifier",
        RandomForestClassifier(
            n_estimators=300,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1
        )
    )

])


# ==========================================
# Train Model
# ==========================================

print("\nTraining model...")

model.fit(X_train, y_train)


# ==========================================
# Evaluate Model
# ==========================================

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\n==========================================")
print("MODEL PERFORMANCE")
print("==========================================")

print(f"Accuracy: {accuracy:.4f}")

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        zero_division=0
    )
)


# ==========================================
# Save Model
# ==========================================

MODEL_PATH = "ai/threat_model.pkl"

with open(MODEL_PATH, "wb") as file:
    pickle.dump(model, file)


print("\n==========================================")
print("SUCCESS")
print("==========================================")
print(f"Enhanced AI model saved to: {MODEL_PATH}")
