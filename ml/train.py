import pandas as pd
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

try:
    from evaluate import evaluate_model, cross_validate_model, print_feature_importance
except ImportError:
    from ml.evaluate import evaluate_model, cross_validate_model, print_feature_importance

# ============================================================
# CHARGEMENT DES DONNEES
# ============================================================
print("Chargement des donnees...")
df = pd.read_csv("data/feature_matrix.csv")

# Features utilisees pour le modele
FEATURE_COLS = [
    "has_weak_prng",
    "has_timing_leak",
    "has_memory_leak",
    "has_weak_params",
    "dangerous_func_count",
    "loc",
    "comment_lines"
]

X = df[FEATURE_COLS]
y = df["label"].astype(int)

print(f"Total fichiers : {len(df)}")
print(f"Securises (0)  : {sum(y == 0)}")
print(f"Vulnerables (1): {sum(y == 1)}")

# ============================================================
# SPLIT TRAIN / TEST
# ============================================================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\nTrain : {len(X_train)} | Test : {len(X_test)}")

# ============================================================
# ENTRAINEMENT RANDOM FOREST
# ============================================================
print("\nEntrainement Random Forest...")
rf_model = RandomForestClassifier(
    n_estimators=100,
    class_weight="balanced",
    random_state=42
)
rf_model.fit(X_train, y_train)

# ============================================================
# EVALUATION
# ============================================================
metrics = evaluate_model(rf_model, X_test, y_test)

print("\n--- Rapport de classification ---")
print(metrics["classification_report"])

print("--- Matrice de confusion ---")
print(metrics["confusion_matrix"])

print(f"\nAUC-ROC : {metrics['auc_roc']:.4f}")

# Cross-validation
cv_results = cross_validate_model(rf_model, X, y, cv=5)
print(f"F1-score cross-validation (5 folds) : {cv_results['mean_f1']:.4f} (+/- {cv_results['std_f1']:.4f})")

# ============================================================
# IMPORTANCE DES FEATURES
# ============================================================
print("\n--- Importance des features ---")
print_feature_importance(rf_model, FEATURE_COLS)

# ============================================================
# SAUVEGARDE DU MODELE
# ============================================================
os.makedirs("models", exist_ok=True)
joblib.dump(rf_model, "models/model.pkl")
joblib.dump(FEATURE_COLS, "models/feature_cols.pkl")
print("\nModele sauvegarde : models/model.pkl")
print("Features sauvegardees : models/feature_cols.pkl")
