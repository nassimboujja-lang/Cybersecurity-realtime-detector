import joblib
import pandas as pd
from pathlib import Path

# Project root: predict_attack.py is inside src/
PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_FILE = PROJECT_ROOT / "models" / "random_forest_attack_detector.joblib"

if not MODEL_FILE.exists():
    raise FileNotFoundError(f"Model not found: {MODEL_FILE}")

# Load saved model and feature names
saved_data = joblib.load(MODEL_FILE)
model = saved_data["model"]
features = saved_data["features"]


def get_risk_and_action(predicted_label, confidence):
    """Return risk level and response action."""

    if predicted_label == "normal":
        return "low", "No action"

    if predicted_label == "brute_force":
        if confidence >= 0.80:
            return "high", "Send alert and temporarily block IP"
        return "medium", "Send alert and monitor IP"

    if predicted_label == "web_scan":
        if confidence >= 0.80:
            return "high", "Send alert and temporarily block IP"
        return "medium", "Send alert and monitor IP"

    if predicted_label == "ddos_like":
        return "critical", "Send urgent alert and temporarily block IP"

    return "unknown", "Manual review required"


def predict_event(event):
    """Predict the attack type for one event."""

    event_df = pd.DataFrame([event])

    X = event_df[features]

    predicted_label = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    confidence = probabilities.max()
    risk_level, action = get_risk_and_action(predicted_label, confidence)

    return {
        "source_ip": event["source_ip"],
        "prediction": predicted_label,
        "confidence": round(float(confidence) * 100, 2),
        "risk_level": risk_level,
        "action": action
    }


new_event = {
    "source_ip": "203.0.113.45",
    "total_requests": 35,
    "get_requests": 8,
    "post_requests": 27,
    "failed_login_attempts": 22,
    "successful_login_attempts": 0,
    "unique_endpoints": 2,
    "error_4xx_count": 22,
    "error_5xx_count": 0,
    "avg_request_interval_ms": 250.0,
    "requests_per_second": 0.58,
    "known_malicious_ip": 1,
    "threat_intelligence_score": 85,
    "is_tor_exit_node": 0
}

result = predict_event(new_event)

print("\n========== PREDICTION RESULT ==========")
print(f"Source IP: {result['source_ip']}")
print(f"Predicted attack: {result['prediction']}")
print(f"Confidence: {result['confidence']}%")
print(f"Risk level: {result['risk_level']}")
print(f"Action: {result['action']}")
