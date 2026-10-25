from pathlib import Path

import pandas as pd

project_root = Path(__file__).resolve().parents[2]

# Files to merge
files = [
    project_root / "raw" / "openphish_raw.csv",
    project_root / "raw" / "nvd_raw.csv",
    project_root / "raw" / "urlhaus_raw.csv",
    project_root / "raw" / "malicious_ips_raw.csv",
]

datasets = []

for path in files:
    if path.exists():
        df = pd.read_csv(path)
        datasets.append(df)
        print(f"Loaded: {path} -> {len(df)} rows")
    else:
        print(f"File not found: {path}")

# Merge all datasets
final_df = pd.concat(datasets, ignore_index=True)

# Remove duplicate indicators from the same source
final_df = final_df.drop_duplicates(
    subset=["source_name", "indicator_type", "indicator_value"]
)

# Sort by collection date
final_df = final_df.sort_values(
    by="collected_at",
    ascending=False
)

# Create final folder if it does not exist
output_dir = project_root / "processed"
output_dir.mkdir(parents=True, exist_ok=True)

# Save final dataset
output_file = output_dir / "threat_intelligence_dataset.csv"
final_df.to_csv(output_file, index=False)

print("\nMerge completed.")
print(f"Final dataset: {len(final_df)} threats")
print("\nThreat types:")
print(final_df["threat_type"].value_counts())

print("\nIndicator types:")
print(final_df["indicator_type"].value_counts())