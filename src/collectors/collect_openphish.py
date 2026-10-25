from pathlib import Path
from datetime import datetime

import pandas as pd
import requests

url = "https://openphish.com/feed.txt"

response = requests.get(url, timeout=30)
response.raise_for_status()

now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

rows = []

for index, phishing_url in enumerate(response.text.splitlines(), start=1):
    phishing_url = phishing_url.strip()

    if phishing_url:
        rows.append({
            "threat_id": f"OP-{index:06d}",
            "source_name": "OpenPhish",
            "source_url": "https://openphish.com/feed.txt",
            "collected_at": now,
            "published_at": None,
            "threat_type": "phishing",
            "indicator_type": "url",
            "indicator_value": phishing_url,
            "severity": "high",
            "cvss_score": None,
            "description": "Phishing URL reported by OpenPhish",
            "malware_family": None,
            "target_product": None,
            "is_actively_exploited": 1,
            "confidence_score": 80,
            "status": "active",
            "first_seen_at": None,
            "last_seen_at": now
        })

df = pd.DataFrame(rows)
output_path = Path(__file__).resolve().parents[2] / "raw" / "openphish_raw.csv"
output_path.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(output_path, index=False)

print(f"{len(df)} phishing URLs collected. Saved to {output_path}")