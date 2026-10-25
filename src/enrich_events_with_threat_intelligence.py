import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

EVENTS_FILE = PROJECT_ROOT / "final" / "security_events_with_real_ips.csv"
THREATS_FILE = PROJECT_ROOT / "clean" / "threats_clean.csv"
OUTPUT_FILE = PROJECT_ROOT / "final" / "security_events_enriched.csv"

events_df = pd.read_csv(EVENTS_FILE)
print(f"Reading events from: {EVENTS_FILE}")
threats_df = pd.read_csv(THREATS_FILE)

# Keep only malicious IP indicators from Threat Intelligence
malicious_ips_df = threats_df[
    threats_df["indicator_type"] == "ip"
].copy()

# Keep one row per IP
malicious_ips_df = malicious_ips_df.drop_duplicates(
    subset=["indicator_value"],
    keep="first"
)

# Dictionary: malicious IP -> confidence score
ip_scores = dict(
    zip(
        malicious_ips_df["indicator_value"].astype(str),
        malicious_ips_df["confidence_score"]
    )
)

# Update each event using Threat Intelligence
events_df["source_ip"] = events_df["source_ip"].astype(str)

events_df["known_malicious_ip"] = events_df["source_ip"].isin(ip_scores).astype(int)

events_df["threat_intelligence_score"] = events_df["source_ip"].map(ip_scores).fillna(0)

events_df["threat_intelligence_score"] = (
    events_df["threat_intelligence_score"]
    .astype(float)
    .clip(0, 100)
)

events_df.to_csv(OUTPUT_FILE, index=False)

print("\n========== THREAT INTELLIGENCE ENRICHMENT ==========")
print(f"Total events: {len(events_df)}")
print(f"Known malicious IP events: {events_df['known_malicious_ip'].sum()}")
print(f"Output saved:\n{OUTPUT_FILE}")