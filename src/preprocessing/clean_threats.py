import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
INPUT_FILE = BASE_DIR / "processed" / "threat_intelligence_dataset.csv"
OUTPUT_FILE = BASE_DIR / "clean" / "threats_clean.csv"

# Lire le dataset fusionné
df = pd.read_csv(INPUT_FILE)

print("Avant nettoyage :", df.shape)

# 1. Supprimer les doublons exacts
df = df.drop_duplicates()

# 2. Supprimer les doublons du même indicateur dans la même source
df = df.drop_duplicates(
    subset=["source_name", "indicator_type", "indicator_value"],
    keep="first"
)

# 3. Nettoyer les colonnes texte
text_columns = [
    "source_name",
    "threat_type",
    "indicator_type",
    "indicator_value",
    "severity",
    "status"
]

for col in text_columns:
    df[col] = df[col].astype(str).str.strip().str.lower()

# Garder les noms de source lisibles
df["source_name"] = df["source_name"].str.title()

# 4. Valeurs autorisées
valid_threat_types = [
    "phishing",
    "malware",
    "malicious_ip",
    "vulnerability"
]

valid_indicator_types = [
    "url",
    "ip",
    "cve"
]

valid_severity = [
    "low",
    "medium",
    "high",
    "critical",
    "unknown"
]

df = df[df["threat_type"].isin(valid_threat_types)]
df = df[df["indicator_type"].isin(valid_indicator_types)]

# Si une gravité est absente ou incorrecte, mettre unknown
df.loc[~df["severity"].isin(valid_severity), "severity"] = "unknown"

# 5. Convertir les dates
date_columns = [
    "collected_at",
    "published_at",
    "first_seen_at",
    "last_seen_at"
]

for col in date_columns:
    df[col] = pd.to_datetime(df[col], errors="coerce")

# 6. CVSS : numérique uniquement pour les vulnérabilités
df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")

# 7. Compléter les valeurs utiles
df["status"] = df["status"].fillna("active")
df["description"] = df["description"].fillna("No description available")
df["malware_family"] = df["malware_family"].fillna("unknown")
df["target_product"] = df["target_product"].fillna("unknown")

# Les dates non fournies restent vides : c'est normal
# On remplace seulement last_seen_at par collected_at si absent
df["last_seen_at"] = df["last_seen_at"].fillna(df["collected_at"])

# 8. Vérifier les plages numériques
df["confidence_score"] = pd.to_numeric(
    df["confidence_score"], errors="coerce"
).fillna(0).clip(0, 100)

df["is_actively_exploited"] = pd.to_numeric(
    df["is_actively_exploited"], errors="coerce"
).fillna(0).astype(int)

# 9. Trier les données
df = df.sort_values(
    by=["collected_at", "severity"],
    ascending=[False, True]
)

# 10. Sauvegarder
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(OUTPUT_FILE, index=False)

print("Après nettoyage :", df.shape)
print("\nMenaces par type :")
print(df["threat_type"].value_counts())

print("\nValeurs manquantes restantes :")
print(df.isnull().sum())

print(f"\nFichier créé : {OUTPUT_FILE}")