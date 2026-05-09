import re
import ast
import os
from crypto_params import WEAK_PARAMS_THRESHOLD
from patterns import (
    MEMORY_LEAK_PATTERNS_C,
    TIMING_LEAK_PATTERNS_C,
    WEAK_PRNG_PATTERNS_C,
    WEAK_PRNG_PATTERNS_PY,
)

# ============================================================
# ANALYSE STATIQUE - Detection de patterns dangereux
# ============================================================

# ============================================================
# DETECTION 1 - PRNG FAIBLE
# ============================================================
def detect_weak_rand(content, lang="c"):
    findings = []

    if lang == "c":
        for pattern, message in WEAK_PRNG_PATTERNS_C:
            for i, line in enumerate(content.splitlines(), 1):
                if re.search(pattern, line):
                    findings.append({
                        "type": "weak_prng",
                        "line": i,
                        "code": line.strip(),
                        "message": message,
                        "severity": "Critique",
                        "recommendation": "Remplacer par randombytes() ou une fonction cryptographique (SHAKE, AES-CTR)"
                    })

    elif lang == "python":
        for pattern, message in WEAK_PRNG_PATTERNS_PY:
            for i, line in enumerate(content.splitlines(), 1):
                if re.search(pattern, line):
                    findings.append({
                        "type": "weak_prng",
                        "line": i,
                        "code": line.strip(),
                        "message": message,
                        "severity": "Critique",
                        "recommendation": "Remplacer par secrets.token_bytes() ou os.urandom()"
                    })

    return findings


# ============================================================
# DETECTION 2 - PARAMETRES FAIBLES
# ============================================================
def detect_weak_params(content, lang="c"):
    findings = []

    if lang == "c":
        for i, line in enumerate(content.splitlines(), 1):
            match = re.search(r'#define\s+(\w*(?:N|K|T)\w*)\s+(\d+)', line)
            if match:
                param_name = match.group(1)
                param_val = int(match.group(2))
                for key, threshold in WEAK_PARAMS_THRESHOLD.items():
                    if param_name.endswith(key) and param_val < threshold:
                        findings.append({
                            "type": "weak_params",
                            "line": i,
                            "code": line.strip(),
                            "message": f"Parametre {param_name}={param_val} inferieur au seuil minimum ({threshold})",
                            "severity": "Elevee",
                            "recommendation": f"Augmenter {param_name} selon les recommandations NIST"
                        })

    elif lang == "python":
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            if target.id in WEAK_PARAMS_THRESHOLD:
                                if isinstance(node.value, ast.Constant):
                                    if isinstance(node.value.value, int):
                                        if node.value.value < WEAK_PARAMS_THRESHOLD[target.id]:
                                            findings.append({
                                                "type": "weak_params",
                                                "line": node.lineno,
                                                "code": f"{target.id} = {node.value.value}",
                                                "message": f"Parametre {target.id}={node.value.value} inferieur au seuil minimum",
                                                "severity": "Elevee",
                                                "recommendation": f"Augmenter {target.id} selon les recommandations NIST"
                                            })
        except SyntaxError:
            pass

    return findings


# ============================================================
# DETECTION 3 - TIMING LEAK
# ============================================================
def detect_timing_leak(content, lang="c"):
    findings = []

    if lang == "c":
        for pattern, message in TIMING_LEAK_PATTERNS_C:
            for i, line in enumerate(content.splitlines(), 1):
                if re.search(pattern, line):
                    findings.append({
                        "type": "timing_leak",
                        "line": i,
                        "code": line.strip(),
                        "message": message,
                        "severity": "Critique",
                        "recommendation": "Remplacer par une comparaison constant-time (crypto_verify, CRYPTO_memcmp)"
                    })

    elif lang == "python":
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Compare):
                    for op in node.ops:
                        if isinstance(op, ast.Eq):
                            findings.append({
                                "type": "timing_leak",
                                "line": node.lineno,
                                "code": f"Comparaison == ligne {node.lineno}",
                                "message": "Comparaison == non constant-time - timing attack possible",
                                "severity": "Critique",
                                "recommendation": "Remplacer par hmac.compare_digest()"
                            })
        except SyntaxError:
            pass

    return findings


# ============================================================
# DETECTION 4 - MEMORY LEAK
# ============================================================
def detect_memory_leak(content, lang="c"):
    findings = []

    if lang == "c":
        for pattern, message in MEMORY_LEAK_PATTERNS_C:
            for i, line in enumerate(content.splitlines(), 1):
                if re.search(pattern, line):
                    findings.append({
                        "type": "memory_leak",
                        "line": i,
                        "code": line.strip(),
                        "message": message,
                        "severity": "Elevee",
                        "recommendation": "Utiliser explicit_bzero() ou memset() suivi d'une barriere memoire"
                    })

    elif lang == "python":
        if "private_key" in content or "_private" in content:
            if "del " not in content and "= None" not in content:
                findings.append({
                    "type": "memory_leak",
                    "line": 0,
                    "code": "Cle privee detectee sans effacement",
                    "message": "Cle privee non effacee apres usage",
                    "severity": "Elevee",
                    "recommendation": "Ajouter del private_key ou private_key = None apres usage"
                })

    return findings


# ============================================================
# ANALYSE COMPLETE D'UN FICHIER
# ============================================================
def analyze_file(filepath):
    result = {
        "file": filepath,
        "language": "",
        "vulnerabilities": [],
        "static_score": 0
    }

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Detecter le langage
        if filepath.endswith('.py'):
            lang = "python"
        else:
            lang = "c"

        result["language"] = lang

        # Lancer les 4 detections
        result["vulnerabilities"] += detect_weak_rand(content, lang)
        result["vulnerabilities"] += detect_weak_params(content, lang)
        result["vulnerabilities"] += detect_timing_leak(content, lang)
        result["vulnerabilities"] += detect_memory_leak(content, lang)

        # Calculer le score statique
        severity_scores = {"Critique": 30, "Elevee": 20, "Moyenne": 10}
        score = 0
        for vuln in result["vulnerabilities"]:
            score += severity_scores.get(vuln["severity"], 10)
        result["static_score"] = min(score, 100)

    except Exception as e:
        print(f"Erreur analyse {filepath}: {e}")

    return result


# ============================================================
# TEST RAPIDE
# ============================================================
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        result = analyze_file(filepath)
        print(f"\nFichier : {result['file']}")
        print(f"Langage : {result['language']}")
        print(f"Score statique : {result['static_score']}%")
        print(f"Vulnerabilites detectees : {len(result['vulnerabilities'])}")
        for v in result['vulnerabilities']:
            print(f"\n  [{v['severity']}] {v['type']} - ligne {v['line']}")
            print(f"      {v['message']}")
            print(f"      {v['recommendation']}")
    else:
        # Test sur un fichier vulnerable
        test_file = "data/vulnerable/mceliece6688128/benes_weak_prng.c"
        if os.path.exists(test_file):
            result = analyze_file(test_file)
            print(f"\nFichier : {result['file']}")
            print(f"Score statique : {result['static_score']}%")
            print(f"Vulnerabilites : {len(result['vulnerabilities'])}")
            for v in result['vulnerabilities']:
                print(f"  [{v['severity']}] ligne {v['line']} - {v['message']}")
        else:
            print("Fichier de test introuvable")
