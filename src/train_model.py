import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

# Project root: train_model.py is inside src/
PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = PROJECT_ROOT / "final" / "security_events_enriched.csv"
MODELS_DIR = PROJECT_ROOT / "models"
MODEL_FILE = MODELS_DIR / "random_forest_attack_detector.joblib"

# Create models folder if it does not exist
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# Check input file
if not INPUT_FILE.exists():
    raise FileNotFoundError(
        f"Dataset not found:\n{INPUT_FILE}\n"
        "Check the file location and name."
    )

# Load dataset
df = pd.read_csv(INPUT_FILE)

# Features used to predict the attack type
features = [
    "total_requests",
    "get_requests",
    "post_requests",
    "failed_login_attempts",
    "successful_login_attempts",
    "unique_endpoints",
    "error_4xx_count",
    "error_5xx_count",
    "avg_request_interval_ms",
    "requests_per_second",
    "known_malicious_ip",
    "threat_intelligence_score",
    "is_tor_exit_node"
]

X = df[features]
y = df["attack_label"]

# Split: 80% train and 20% test
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# Train Random Forest
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)

# Predict test data
y_pred = model.predict(X_test)

# Evaluation
accuracy = accuracy_score(y_test, y_pred)

print("\n========== MODEL RESULTS ==========")
print(f"Dataset size: {df.shape}")
print(f"Training rows: {len(X_train)}")
print(f"Testing rows: {len(X_test)}")
print(f"\nAccuracy: {accuracy * 100:.2f}%")

print("\nClassification report:")
print(classification_report(y_test, y_pred))

print("Confusion matrix:")
print(confusion_matrix(y_test, y_pred))

# Save model and feature list together
joblib.dump(
    {
        "model": model,
        "features": features
    },
    MODEL_FILE
)

print(f"\nModel saved successfully:\n{MODEL_FILE}")