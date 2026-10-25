import joblib
import pandas as pd
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_FILE = PROJECT_ROOT / "models" / "random_forest_attack_detector.joblib"
INPUT_FILE = PROJECT_ROOT / "final" / "security_events_enriched.csv"
ALERTS_DIR = PROJECT_ROOT / "alerts"
OUTPUT_FILE = ALERTS_DIR / "alerts.csv"

ALERTS_DIR.mkdir(parents=True, exist_ok=True)

saved_data = joblib.load(MODEL_FILE)
model = saved_data["model"]
features = saved_data["features"]

df = pd.read_csv(INPUT_FILE)

X = df[features]

df["predicted_attack"] = model.predict(X)
df["confidence"] = model.predict_proba(X).max(axis=1) * 100


def get_risk_and_action(prediction, confidence):
    if prediction == "normal":
        return "low", "No action"

    if prediction in ["brute_force", "web_scan"]:
        if confidence >= 80:
            return "high", "Send alert and temporarily block IP"
        return "medium", "Send alert and monitor IP"

    if prediction == "ddos_like":
        return "critical", "Send urgent alert and temporarily block IP"

    return "unknown", "Manual review required"


results = df.apply(
    lambda row: get_risk_and_action(
        row["predicted_attack"],
        row["confidence"]
    ),
    axis=1
)

df["risk_level"] = [result[0] for result in results]
df["action"] = [result[1] for result in results]

alerts_df = df[df["risk_level"].isin(["high", "critical"])].copy()

alerts_df["alert_created_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

alert_columns = [
    "alert_created_at",
    "event_id",
    "timestamp",
    "source_ip",
    "predicted_attack",
    "confidence",
    "risk_level",
    "action",
    "total_requests",
    "failed_login_attempts",
    "unique_endpoints",
    "known_malicious_ip",
    "threat_intelligence_score"
]

alerts_df[alert_columns].to_csv(OUTPUT_FILE, index=False)

print("\n========== PROCESSING RESULTS ==========")
print(f"Total events analyzed: {len(df)}")
print(f"Dangerous alerts created: {len(alerts_df)}")

print("\nAlerts by predicted attack:")
print(alerts_df["predicted_attack"].value_counts())

print(f"\nAlerts file saved:\n{OUTPUT_FILE}")