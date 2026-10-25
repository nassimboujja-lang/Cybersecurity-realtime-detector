import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

EVENTS_FILE = PROJECT_ROOT / "final" / "security_events_dataset.csv"
THREATS_FILE = PROJECT_ROOT / "clean" / "threats_clean.csv"
OUTPUT_FILE = PROJECT_ROOT / "final" / "security_events_with_real_ips.csv"

events_df = pd.read_csv(EVENTS_FILE)
threats_df = pd.read_csv(THREATS_FILE)

# Get public malicious IPs from threat intelligence
malicious_ips = threats_df[
    threats_df["indicator_type"] == "ip"
]["indicator_value"].dropna().astype(str).unique().tolist()

if not malicious_ips:
    raise ValueError("No malicious IPs found in threats_clean.csv")

# Only attack events receive real malicious IPs
attack_mask = events_df["attack_label"] != "normal"
attack_indices = events_df[attack_mask].sample(
    n=min(600, attack_mask.sum()),
    random_state=42
).index

# Put malicious IPs into 600 attack events
for position, index in enumerate(attack_indices):
    events_df.loc[index, "source_ip"] = malicious_ips[position % len(malicious_ips)]

events_df.to_csv(OUTPUT_FILE, index=False)

print("\n========== MALICIOUS IP INJECTION ==========")
print(f"Total events: {len(events_df)}")
print(f"Attack events updated with real malicious IPs: {len(attack_indices)}")
print(f"Output saved:\n{OUTPUT_FILE}")