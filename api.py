import sys
sys.path.insert(0, 'src')

import os
import joblib
import tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import pandas as pd

from src.features import extract_features_c, extract_features_py
from scoring import compute_global_score, format_score_report, get_severity
from src.static_analysis import analyze_file

# ============================================================
# CHARGEMENT DU MODELE
# ============================================================
MODEL_PATH = "models/model.pkl"
FEATURES_PATH = "models/feature_cols.pkl"

model = joblib.load(MODEL_PATH)
feature_cols = joblib.load(FEATURES_PATH)

# ============================================================
# APPLICATION FASTAPI
# ============================================================
app = FastAPI(
    title="Crypto Vulnerability Detector",
    description="Detection de vulnerabilites dans le code cryptographique post-quantique",
    version="1.0.0"
)

# ============================================================
# ENDPOINT HEALTH
# ============================================================
@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0"}

# ============================================================
# ENDPOINT ANALYZE
# ============================================================
@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    # Lire le fichier uploade
    content = await file.read()
    filename = file.filename

    # Sauvegarder temporairement
    if filename.endswith(".py"):
        suffix = ".py"
    elif filename.endswith((".c", ".h")):
        suffix = ".c"
    else:
        raise HTTPException(status_code=400, detail="Type de fichier non supporte")

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        # Extraction des features
        if suffix == ".py":
            features = extract_features_py(tmp_path)
        else:
            features = extract_features_c(tmp_path)

        # Prediction ML
        feature_vector = pd.DataFrame([features])[feature_cols]
        ml_score = float(model.predict_proba(feature_vector)[0][1]) * 100

        # Analyse statique
        static_result = analyze_file(tmp_path)
        static_score = static_result["static_score"]

        # Score global combine
        global_score = compute_global_score(ml_score, static_score)

        # Niveau de severite
        severity = get_severity(global_score)

        # Construire la reponse
        response = {
            "file": filename,
            **format_score_report(
                ml_score=ml_score,
                static_score=static_score,
                global_score=global_score,
                severity=severity,
                vulnerabilities=static_result["vulnerabilities"],
                metrics={
                    "loc": features["loc"],
                    "comment_lines": features["comment_lines"],
                    "dangerous_func_count": features["dangerous_func_count"]
                },
            ),
        }

    finally:
        os.unlink(tmp_path)

    return JSONResponse(content=response)

# ============================================================
# LANCEMENT
# ============================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
