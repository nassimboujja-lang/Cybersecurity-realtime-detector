from pathlib import Path
from datetime import datetime

import pandas as pd
import requests

# Liste d'IP qui ont essayé des attaques SSH, mail, FTP ou web
BLOCKLIST_URL = "https://lists.blocklist.de/lists/all.txt"

response = requests.get(BLOCKLIST_URL, timeout=60)
response.raise_for_status()

now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

ips = []

for line in response.text.splitlines():
    ip = line.strip()

    # Ignorer les lignes vides et commentaires
    if not ip or ip.startswith("#"):
        continue

    ips.append(ip)

# Garder seulement 300 IP
ips = ips[:300]

rows = []

for index, ip in enumerate(ips, start=1):
    rows.append({
        "threat_id": f"BL-{index:06d}",
        "source_name": "blocklist.de",
        "source_url": "https://www.blocklist.de/en/export.html",
        "collected_at": now,
        "published_at": None,
        "threat_type": "malicious_ip",
        "indicator_type": "ip",
        "indicator_value": ip,
        "severity": "medium",
        "cvss_score": None,
        "description": "IP address listed in blocklist.de as suspicious or malicious",
        "malware_family": None,
        "target_product": None,
        "is_actively_exploited": 0,
        "confidence_score": 75,
        "status": "active",
        "first_seen_at": None,
        "last_seen_at": now
    })

df = pd.DataFrame(rows)
output_path = Path(__file__).resolve().parents[2] / "raw" / "malicious_ips_raw.csv"
output_path.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(output_path, index=False)

print(f"{len(df)} IP malveillantes collectées depuis blocklist.de. Saved to {output_path}")