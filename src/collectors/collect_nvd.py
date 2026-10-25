from pathlib import Path
from datetime import datetime, timedelta

import pandas as pd
import requests

end_date = datetime.utcnow()
start_date = end_date - timedelta(days=7)

params = {
    "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
    "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
    "resultsPerPage": 100
}

response = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    params=params,
    timeout=60
)
response.raise_for_status()

data = response.json()
now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

rows = []

for item in data.get("vulnerabilities", []):
    cve = item["cve"]
    cve_id = cve["id"]

    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    metrics = cve.get("metrics", {})
    cvss_score = None

    if "cvssMetricV31" in metrics:
        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV30" in metrics:
        cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

    if cvss_score is None:
        severity = "unknown"
    elif cvss_score >= 9:
        severity = "critical"
    elif cvss_score >= 7:
        severity = "high"
    elif cvss_score >= 4:
        severity = "medium"
    else:
        severity = "low"

    rows.append({
        "threat_id": cve_id,
        "source_name": "NVD",
        "source_url": "https://nvd.nist.gov/",
        "collected_at": now,
        "published_at": cve.get("published"),
        "threat_type": "vulnerability",
        "indicator_type": "cve",
        "indicator_value": cve_id,
        "severity": severity,
        "cvss_score": cvss_score,
        "description": description,
        "malware_family": None,
        "target_product": None,
        "is_actively_exploited": 0,
        "confidence_score": 95,
        "status": "active",
        "first_seen_at": cve.get("published"),
        "last_seen_at": cve.get("lastModified")
    })

df = pd.DataFrame(rows)
output_path = Path(__file__).resolve().parents[2] / "raw" / "nvd_raw.csv"
output_path.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(output_path, index=False)

print(f"{len(df)} CVEs collected. Saved to {output_path}")