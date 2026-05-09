import os
import ast
import re
import csv
from crypto_params import WEAK_PARAMS_THRESHOLD
from patterns import DANGEROUS_FUNCTIONS_C, DANGEROUS_FUNCTIONS_PY

# ============================================================
# CONFIGURATION
# ============================================================
DATA_DIR = "data"
OUTPUT_CSV = "data/feature_matrix.csv"
DATASET_CSV = "data/dataset.csv"

# ============================================================
# FEATURE EXTRACTION POUR FICHIERS C
# ============================================================
def extract_features_c(filepath):
    features = {
        "has_weak_prng": 0,
        "has_timing_leak": 0,
        "has_memory_leak": 0,
        "has_weak_params": 0,
        "dangerous_func_count": 0,
        "loc": 0,
        "comment_lines": 0,
        "vuln_comment_count": 0
    }

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            content = ''.join(lines)

        features["loc"] = len(lines)

        # Compter les commentaires
        features["comment_lines"] = sum(
            1 for l in lines if l.strip().startswith("//") or l.strip().startswith("*")
        )

        # Compter les commentaires VULN
        features["vuln_comment_count"] = content.count("VULN")

        # Detecter PRNG faible
        if re.search(r'\brand\s*\(', content) or re.search(r'\bsrand\s*\(', content):
            features["has_weak_prng"] = 1

        # Detecter timing leak
        if re.search(r'\bmemcmp\s*\(', content) or re.search(r'\bstrcmp\s*\(', content):
            features["has_timing_leak"] = 1

        # Detecter memory leak (memset commente ou absent)
        if "VULN: memset removed" in content or "//memset" in content:
            features["has_memory_leak"] = 1

        # Detecter parametres faibles
        weak_pattern = re.findall(r'#define\s+\w*(?:N|K|T)\w*\s+(\d+)', content)
        for val in weak_pattern:
            if int(val) < 100:
                features["has_weak_params"] = 1
                break

        # Compter les fonctions dangereuses
        for func in DANGEROUS_FUNCTIONS_C:
            features["dangerous_func_count"] += len(
                re.findall(r'\b' + func + r'\s*\(', content)
            )

    except Exception as e:
        print(f"Erreur lecture {filepath}: {e}")

    return features


# ============================================================
# FEATURE EXTRACTION POUR FICHIERS PYTHON
# ============================================================
def extract_features_py(filepath):
    features = {
        "has_weak_prng": 0,
        "has_timing_leak": 0,
        "has_memory_leak": 0,
        "has_weak_params": 0,
        "dangerous_func_count": 0,
        "loc": 0,
        "comment_lines": 0,
        "vuln_comment_count": 0
    }

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            content = ''.join(lines)

        features["loc"] = len(lines)

        # Compter les commentaires
        features["comment_lines"] = sum(
            1 for l in lines if l.strip().startswith("#")
        )

        # Compter les commentaires VULN
        features["vuln_comment_count"] = content.count("VULN")

        # Parser AST
        try:
            tree = ast.parse(content)
            dangerous_py_names = [name.split(".")[-1] for name in DANGEROUS_FUNCTIONS_PY]
            for node in ast.walk(tree):
                # Detecter appels dangereux
                if isinstance(node, ast.Call):
                    func_name = ""
                    if isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    elif isinstance(node.func, ast.Name):
                        func_name = node.func.id

                    if func_name in dangerous_py_names:
                        features["has_weak_prng"] = 1
                        features["dangerous_func_count"] += 1

                # Detecter comparaisons == sur donnees sensibles
                if isinstance(node, ast.Compare):
                    for op in node.ops:
                        if isinstance(op, ast.Eq):
                            features["has_timing_leak"] = 1

                # Detecter parametres faibles
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            if target.id in WEAK_PARAMS_THRESHOLD:
                                if isinstance(node.value, ast.Constant):
                                    if isinstance(node.value.value, int):
                                        if node.value.value < 100:
                                            features["has_weak_params"] = 1

        except SyntaxError:
            pass

        # Detecter memory leak
        if "VULN" in content and "private_key" in content:
            if "del " not in content and "None" not in content:
                features["has_memory_leak"] = 1

    except Exception as e:
        print(f"Erreur lecture {filepath}: {e}")

    return features


# ============================================================
# PROGRAMME PRINCIPAL
# ============================================================
def main():
    print("Extraction des features...")

    rows = []

    # Lire le dataset.csv
    with open(DATASET_CSV, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        dataset = list(reader)

    for entry in dataset:
        file_path = entry["file_path"].replace("\\", "/")
        full_path = os.path.join(DATA_DIR, file_path)

        if not os.path.exists(full_path):
            continue

        # Extraire les features selon le type de fichier
        if full_path.endswith('.py'):
            features = extract_features_py(full_path)
        else:
            features = extract_features_c(full_path)

        # Construire la ligne
        row = {
            "file_path": file_path,
            "label": entry["label"],
            "vulnerability_type": entry["vulnerability_type"],
            **features
        }
        rows.append(row)

    # Sauvegarder la matrice
    if rows:
        fieldnames = list(rows[0].keys())
        with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        print(f"Feature matrix sauvegardee : {OUTPUT_CSV}")
        print(f"Nombre de fichiers traites : {len(rows)}")

        # Statistiques
        vulnerable = sum(1 for r in rows if r["label"] == "1")
        secure = sum(1 for r in rows if r["label"] == "0")
        print(f"Fichiers securises : {secure}")
        print(f"Fichiers vulnerables : {vulnerable}")


if __name__ == "__main__":
    main()
