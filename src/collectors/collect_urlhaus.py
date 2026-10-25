from pathlib import Path
from datetime import datetime
from io import StringIO

import pandas as pd
import requests

URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

response = requests.get(URLHAUS_URL, timeout=60)
response.raise_for_status()

# Le fichier URLhaus contient des lignes de commentaire qui commencent par #
lines = [
    line for line in response.text.splitlines()
    if line.strip() and not line.startswith("#")
]

# Colonnes officielles du CSV URLhaus
columns = [
    "id",
    "dateadded",
    "url",
    "url_status",
    "last_online",
    "threat",
    "tags",
    "urlhaus_link",
    "reporter"
]

raw_df = pd.read_csv(
    StringIO("\n".join(lines)),
    header=None,
    names=columns
)

# Garder uniquement 300 URLs actives/récentes
raw_df = raw_df.head(400)

now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

rows = []

for index, row in raw_df.iterrows():
    tags = str(row["tags"]) if pd.notna(row["tags"]) else ""

    # Essayer de trouver une famille de malware dans les tags
    malware_family = tags if tags != "nan" else None

    rows.append({
        "threat_id": f"UH-{row['id']}",
        "source_name": "URLhaus",
        "source_url": "https://urlhaus.abuse.ch/",
        "collected_at": now,
        "published_at": row["dateadded"],
        "threat_type": "malware",
        "indicator_type": "url",
        "indicator_value": row["url"],
        "severity": "high",
        "cvss_score": None,
        "description": f"Malware URL reported by URLhaus. Threat: {row['threat']}",
        "malware_family": malware_family,
        "target_product": None,
        "is_actively_exploited": 1 if row["url_status"] == "online" else 0,
        "confidence_score": 90,
        "status": "active" if row["url_status"] == "online" else "inactive",
        "first_seen_at": row["dateadded"],
        "last_seen_at": row["last_online"]
    })

df = pd.DataFrame(rows)
output_path = Path(__file__).resolve().parents[2] / "raw" / "urlhaus_raw.csv"
output_path.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(output_path, index=False)

print(f"{len(df)} URLs malware collectées depuis URLhaus. Saved to {output_path}")