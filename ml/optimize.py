import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, train_test_split


FEATURE_COLS = [
    "has_weak_prng",
    "has_timing_leak",
    "has_memory_leak",
    "has_weak_params",
    "dangerous_func_count",
    "loc",
    "comment_lines",
]


def optimize_random_forest(X_train, y_train) -> dict:
    """Optimise un Random Forest avec GridSearchCV et retourne le meilleur modele."""
    param_grid = {
        "n_estimators": [50, 100, 200],
        "max_depth": [None, 10, 20],
        "min_samples_split": [2, 5, 10],
    }
    model = RandomForestClassifier(class_weight="balanced", random_state=42)
    grid = GridSearchCV(model, param_grid, cv=5, scoring="f1", n_jobs=-1)
    grid.fit(X_train, y_train)

    return {
        "best_params": grid.best_params_,
        "best_score": float(grid.best_score_),
        "model": grid.best_estimator_,
    }


def run_optimization() -> None:
    """Charge la matrice de features, lance l'optimisation et affiche le resultat."""
    df = pd.read_csv("data/feature_matrix.csv")
    X = df[FEATURE_COLS]
    y = df["label"].astype(int)
    X_train, _, y_train, _ = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    result = optimize_random_forest(X_train, y_train)
    print("Meilleurs parametres :", result["best_params"])
    print(f"Meilleur score F1 : {result['best_score']:.4f}")


if __name__ == "__main__":
    run_optimization()
