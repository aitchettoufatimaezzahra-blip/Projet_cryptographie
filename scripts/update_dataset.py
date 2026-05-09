import os
import csv

csv_path = "data/dataset.csv"
secure_dir = "data/secure/mceliece6688128"
vulnerable_dir = "data/vulnerable/mceliece6688128"

new_rows = []

# Ajouter les fichiers sécurisés
for filename in os.listdir(secure_dir):
    if filename.endswith(('.c', '.h')):
        new_rows.append({
            "file_path": f"secure/mceliece6688128/{filename}",
            "label": "0",
            "vulnerability_type": "none",
            "severity": "none",
            "description": "Implementation de reference Classic McEliece 6688128",
            "source": "PQClean/mceliece6688128"
        })

# Ajouter les fichiers vulnérables
vuln_types = {
    "weak_prng": "Critique",
    "weak_params": "Elevee",
    "timing_leak": "Critique",
    "memory_leak": "Elevee"
}

for filename in os.listdir(vulnerable_dir):
    if filename.endswith(('.c', '.h')):
        vuln_type = None
        for vt in vuln_types:
            if vt in filename:
                vuln_type = vt
                break
        if vuln_type:
            # Retrouver le fichier source original
            original = filename.replace(f"_{vuln_type}", "")
            new_rows.append({
                "file_path": f"vulnerable/mceliece6688128/{filename}",
                "label": "1",
                "vulnerability_type": vuln_type,
                "severity": vuln_types[vuln_type],
                "description": f"Mutation: {vuln_type}",
                "source": f"mutated_from:secure/mceliece6688128/{original}"
            })

# Ajouter au CSV existant
with open(csv_path, 'a', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=["file_path","label","vulnerability_type","severity","description","source"])
    writer.writerows(new_rows)

print(f"✅ {len(new_rows)} lignes ajoutées au dataset.csv")

# Compter le total
with open(csv_path, 'r', encoding='utf-8') as f:
    total = sum(1 for line in f)
print(f"✅ Total dataset.csv : {total} lignes")