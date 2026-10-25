import pandas as pd
import random
from faker import Faker
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
OUTPUT_DIR = BASE_DIR / "final"
OUTPUT_FILE = OUTPUT_DIR / "security_events_dataset.csv"

fake = Faker()
random.seed(42)

rows = []
event_number = 1

def risk_level(label):
    levels = {
        "normal": "low",
        "brute_force": "high",
        "web_scan": "high",
        "ddos_like": "critical"
    }
    return levels[label]

def add_event(label, total_range, failed_range, success_range,
              unique_urls_range, error4xx_range, interval_range,
              malicious_probability, ti_score_range):

    global event_number

    total_requests = random.randint(*total_range)
    failed_logins = random.randint(*failed_range)
    successful_logins = random.randint(*success_range)
    unique_endpoints = random.randint(*unique_urls_range)
    error_4xx = random.randint(*error4xx_range)
    avg_interval = random.uniform(*interval_range)

    get_requests = random.randint(
        max(0, total_requests // 2),
        total_requests
    )
    post_requests = total_requests - get_requests

    known_malicious_ip = int(
        random.random() < malicious_probability
    )

    threat_score = random.randint(*ti_score_range)
    requests_per_second = round(total_requests / 60, 2)

    rows.append({
        "event_id": f"EVT-{event_number:06d}",
        "timestamp": (
            datetime.now() - timedelta(
                minutes=random.randint(0, 10000)
            )
        ).strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": fake.ipv4_private(),
        "time_window_seconds": 60,
        "total_requests": total_requests,
        "get_requests": get_requests,
        "post_requests": post_requests,
        "failed_login_attempts": failed_logins,
        "successful_login_attempts": successful_logins,
        "unique_endpoints": unique_endpoints,
        "error_4xx_count": error_4xx,
        "error_5xx_count": random.randint(0, 2),
        "avg_request_interval_ms": round(avg_interval, 2),
        "requests_per_second": requests_per_second,
        "known_malicious_ip": known_malicious_ip,
        "threat_intelligence_score": threat_score,
        "is_tor_exit_node": random.choice([0, 0, 0, 1]),
        "attack_label": label,
        "risk_level": risk_level(label)
    })

    event_number += 1


# 1. Normal traffic — 1,000 rows
for _ in range(1000):
    add_event(
        "normal",
        total_range=(1, 20),
        failed_range=(0, 2),
        success_range=(0, 3),
        unique_urls_range=(1, 6),
        error4xx_range=(0, 2),
        interval_range=(2500, 15000),
        malicious_probability=0.01,
        ti_score_range=(0, 15)
    )

# 2. Brute-force attacks — 1,000 rows
for _ in range(1000):
    add_event(
        "brute_force",
        total_range=(10, 70),
        failed_range=(5, 35),
        success_range=(0, 1),
        unique_urls_range=(1, 4),
        error4xx_range=(5, 35),
        interval_range=(50, 800),
        malicious_probability=0.25,
        ti_score_range=(40, 100)
    )

# 3. Web scans — 1,000 rows
for _ in range(1000):
    add_event(
        "web_scan",
        total_range=(25, 120),
        failed_range=(0, 4),
        success_range=(0, 1),
        unique_urls_range=(15, 70),
        error4xx_range=(10, 80),
        interval_range=(30, 1000),
        malicious_probability=0.15,
        ti_score_range=(20, 90)
    )

# 4. DDoS-like traffic — 1,000 rows
for _ in range(1000):
    add_event(
        "ddos_like",
        total_range=(150, 700),
        failed_range=(0, 5),
        success_range=(0, 2),
        unique_urls_range=(1, 20),
        error4xx_range=(0, 20),
        interval_range=(5, 100),
        malicious_probability=0.20,
        ti_score_range=(30, 100)
    )

df = pd.DataFrame(rows)

# Shuffle the rows so classes are mixed
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
df.to_csv(OUTPUT_FILE, index=False)

print("Dataset created:", df.shape)
print("\nClasses:")
print(df["attack_label"].value_counts())
print("\nSaved to:", OUTPUT_FILE)