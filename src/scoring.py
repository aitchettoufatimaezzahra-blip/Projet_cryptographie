def compute_global_score(ml_score: float, static_score: int) -> float:
    """Calcule le score global en combinant le score ML et le score statique."""
    return round((ml_score * 0.6) + (static_score * 0.4), 2)


def get_severity(global_score: float) -> str:
    """Retourne le niveau de severite associe au score global."""
    if global_score <= 25:
        return "Faible"
    if global_score <= 50:
        return "Moyen"
    if global_score <= 75:
        return "Eleve"
    return "Critique"


def format_score_report(
    ml_score,
    static_score,
    global_score,
    severity,
    vulnerabilities,
    metrics,
) -> dict:
    """Construit le dictionnaire JSON complet du rapport d'analyse."""
    return {
        "ml_score": round(ml_score, 2),
        "static_score": static_score,
        "global_score": global_score,
        "severity": severity,
        "vulnerabilities": vulnerabilities,
        "metrics": metrics,
    }
