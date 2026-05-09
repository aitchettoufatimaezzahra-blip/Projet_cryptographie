import json
import os
from datetime import datetime


REPORTS_DIR = "reports"


def get_report_path(filename: str) -> str:
    """Retourne le chemin du rapport JSON a sauvegarder."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.basename(filename).replace(" ", "_")
    return os.path.join(REPORTS_DIR, f"{timestamp}_{base_name}.json")


def generate_json_report(result: dict, filename: str) -> str:
    """Sauvegarde le resultat d'analyse au format JSON dans le dossier reports."""
    report_path = get_report_path(filename)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    return report_path


def generate_summary(result: dict) -> str:
    """Genere un resume lisible de l'analyse de vulnerabilites."""
    vulnerabilities = result.get("vulnerabilities", [])
    metrics = result.get("metrics", {})
    lines = [
        f"Fichier : {result.get('file', 'inconnu')}",
        f"Score ML : {result.get('ml_score', 0)}%",
        f"Score statique : {result.get('static_score', 0)}%",
        f"Score global : {result.get('global_score', 0)}%",
        f"Severite : {result.get('severity', 'Inconnue')}",
        f"Lignes de code : {metrics.get('loc', 0)}",
        f"Fonctions dangereuses : {metrics.get('dangerous_func_count', 0)}",
        f"Vulnerabilites detectees : {len(vulnerabilities)}",
    ]

    for vuln in vulnerabilities:
        lines.append(
            f"- [{vuln.get('severity', 'Inconnue')}] "
            f"{vuln.get('type', 'vulnerabilite')} ligne {vuln.get('line', 0)} : "
            f"{vuln.get('message', '')}"
        )

    return "\n".join(lines)
