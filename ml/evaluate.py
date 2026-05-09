from sklearn.metrics import classification_report, confusion_matrix, f1_score, roc_auc_score
from sklearn.model_selection import cross_val_score


def evaluate_model(model, X_test, y_test) -> dict:
    """Evalue un modele entraine sur un jeu de test et retourne les metriques."""
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    return {
        "classification_report": classification_report(
            y_test,
            y_pred,
            target_names=["Securise", "Vulnerable"],
        ),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "auc_roc": float(roc_auc_score(y_test, y_proba)),
        "f1_score": float(f1_score(y_test, y_pred)),
    }


def cross_validate_model(model, X, y, cv=5) -> dict:
    """Execute une validation croisee et retourne les scores F1."""
    scores = cross_val_score(model, X, y, cv=cv, scoring="f1")
    return {
        "mean_f1": float(scores.mean()),
        "std_f1": float(scores.std()),
        "scores": scores.tolist(),
    }


def print_feature_importance(model, feature_cols: list) -> None:
    """Affiche les importances des features triees par ordre decroissant."""
    importances = zip(feature_cols, model.feature_importances_)
    for feat, imp in sorted(importances, key=lambda x: x[1], reverse=True):
        print(f"  {feat:30s} : {imp:.4f}")
