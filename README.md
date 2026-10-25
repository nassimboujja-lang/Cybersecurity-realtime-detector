# Network Attack Detector

A machine-learning project that classifies web traffic into **normal** activity or one of three attack types, based on per-IP request statistics over 60-second windows.

## Attack classes

| Label | Description |
|---|---|
| `normal` | Regular user traffic |
| `ddos_like` | Very high request rate, tiny request intervals |
| `web_scan` | Many distinct endpoints probed, elevated 4xx/5xx errors |
| `brute_force` | Repeated failed login attempts |

Each event also carries a `risk_level` (`low`, `high`, `critical`).

## Files

| File | Purpose |
|---|---|
| `security_events_dataset.csv` | Base synthetic dataset (4,000 events, 1,000 per class) |
| `security_events_with_real_ips.csv` | Same events with realistic public source IPs and varied threat scores |
| `security_events_enriched.csv` | Threat-intelligence-enriched version (malicious-IP flag, score of 0 or 75) |
| `random_forest_attack_detector.joblib` | Trained model bundle (dict with `model` and `features`) |

## Data schema

`event_id`, `timestamp`, `source_ip`, `time_window_seconds` (always 60), plus the features below and the labels `attack_label` and `risk_level`.

**Model features (13):** `total_requests`, `get_requests`, `post_requests`, `failed_login_attempts`, `successful_login_attempts`, `unique_endpoints`, `error_4xx_count`, `error_5xx_count`, `avg_request_interval_ms`, `requests_per_second`, `known_malicious_ip`, `threat_intelligence_score`, `is_tor_exit_node`.

## Model

`RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42)` from scikit-learn, trained to predict `attack_label`.

## Usage

```python
import joblib
import pandas as pd

bundle = joblib.load("random_forest_attack_detector.joblib")
model, features = bundle["model"], bundle["features"]

df = pd.read_csv("security_events_enriched.csv")
df["predicted_attack"] = model.predict(df[features])
print(df[["event_id", "source_ip", "predicted_attack"]].head())
```

## Requirements

Python 3, `scikit-learn`, `pandas`, `joblib`. The model was saved with scikit-learn 1.9.0, so load it with the same version to avoid warnings.

## Notes

- The data is synthetic and perfectly balanced, so real-world performance will differ. Validate on genuine traffic before relying on it.
- `source_ip` and `event_id` are identifiers and are not used as model features.
