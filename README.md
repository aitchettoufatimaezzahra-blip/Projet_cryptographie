# 🔐 Prédiction de Vulnérabilités en Code-Based Cryptography

> Système intelligent de détection automatique de vulnérabilités dans les implémentations de cryptographie post-quantique basée sur les codes correcteurs d'erreurs.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green?logo=fastapi)
![Scikit-learn](https://img.shields.io/badge/scikit--learn-1.3+-orange?logo=scikitlearn)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-red?logo=streamlit)
![License](https://img.shields.io/badge/License-Academic-lightgrey)

---

## 📋 Table des Matières

- [À Propos du Projet](#-à-propos-du-projet)
- [Fonctionnalités](#-fonctionnalités)
- [Architecture](#-architecture)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Structure du Projet](#-structure-du-projet)
- [Dataset](#-dataset)
- [Modèle ML](#-modèle-ml)
- [API Reference](#-api-reference)
- [Tests](#-tests)
- [Équipe](#-équipe)
- [Références](#-références)

---

## 🧠 À Propos du Projet

Avec l'émergence des ordinateurs quantiques, les algorithmes classiques comme RSA et ECC deviennent vulnérables. La **cryptographie basée sur les codes correcteurs d'erreurs** (ex : McEliece, BIKE, HQC) est une alternative post-quantique solide — mais une mauvaise implémentation peut ruiner toute la sécurité mathématique.

Ce projet propose un **pipeline complet** qui :

1. Analyse statiquement du code source (C / Python)
2. Extrait des features via parsing AST et métriques de complexité
3. Prédit via Machine Learning si le code est vulnérable
4. Retourne un score de risque (0–100 %) et des recommandations

---

## ✨ Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| 🔍 Analyse statique | Détection de patterns dangereux sans exécution du code |
| 🌳 Parsing AST | Parcours de l'arbre syntaxique abstrait (Python + C) |
| 🤖 Prédiction ML | Classification vulnérable / sécurisé par Random Forest / XGBoost |
| 📊 Score de risque | Score global 0–100 % avec niveau de sévérité |
| 📝 Rapport | Liste des vulnérabilités + recommandations de correction |
| ⚡ API REST | Endpoint FastAPI documenté (Swagger auto-généré) |
| 🖥️ Interface web | Interface Streamlit simple et rapide |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Code Source (.py / .c)             │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│            Feature Extraction Module                 │
│   AST Parsing · Métriques · Patterns statiques      │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│              ML Prediction Model                     │
│        Random Forest / XGBoost (Classification)     │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│              Risk Scoring Engine                     │
│          Score ML + Score Statique → 0–100 %        │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│         Reporting Dashboard (API + Interface)        │
│     Score · Vulnérabilités · Recommandations        │
└─────────────────────────────────────────────────────┘
```

---

## 📦 Prérequis

- **Python** 3.10 ou supérieur
- **pip** (gestionnaire de paquets Python)
- **Git**
- Système : Linux / macOS / Windows

---

## 🚀 Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/votre-username/crypto-vuln-detector.git
cd crypto-vuln-detector
```

### 2. Créer un environnement virtuel

```bash
python -m venv venv

# Linux / macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 4. Vérifier l'installation

```bash
python -c "import sklearn, fastapi, streamlit; print('Installation OK')"
```

---

## 🎯 Utilisation

### Option 1 — Interface Web (recommandée)

Lancer l'interface Streamlit :

```bash
streamlit run app.py
```

Ouvrir le navigateur à l'adresse `http://localhost:8501`, uploader un fichier `.py` ou `.c` et consulter le rapport.

---

### Option 2 — API REST

Démarrer le serveur FastAPI :

```bash
uvicorn api:app --reload --host 0.0.0.0 --port 8000
```

Envoyer une requête d'analyse :

```bash
curl -X POST "http://localhost:8000/analyze" \
     -H "accept: application/json" \
     -F "file=@mon_code.py"
```

Réponse JSON :

```json
{
  "risk_score": 73.4,
  "severity": "HIGH",
  "vulnerabilities": [
    {
      "type": "WEAK_RANDOM",
      "line": 12,
      "description": "Utilisation de random.randint() pour la génération de clés",
      "severity": "CRITICAL"
    },
    {
      "type": "WEAK_PARAMS",
      "line": 5,
      "description": "Paramètre n=64 inférieur au minimum recommandé (n≥1024)",
      "severity": "HIGH"
    }
  ],
  "recommendations": [
    "Remplacer random.randint() par secrets.randbits() ou os.urandom()",
    "Augmenter le paramètre n à 1024 minimum pour McEliece standard"
  ],
  "metrics": {
    "loc": 87,
    "cyclomatic_complexity": 12,
    "num_functions": 5
  }
}
```

Documentation interactive Swagger disponible à : `http://localhost:8000/docs`

---

### Option 3 — Script Python directement

```python
from features import extract_features
from static_analysis import detect_patterns
from scoring import compute_risk_score
import joblib

# Charger le modèle
model = joblib.load("model.pkl")

# Lire le fichier à analyser
with open("mon_code.py", "r") as f:
    code = f.read()

# Pipeline complet
features = extract_features(code)
patterns = detect_patterns(code)
ml_score = model.predict_proba([features])[0][1] * 100
final_score = compute_risk_score(ml_score, patterns)

print(f"Score de risque : {final_score:.1f}%")
print(f"Vulnérabilités détectées : {len(patterns)}")
```

---

## 📁 Structure du Projet

```
crypto-vuln-detector/
│
├── data/                        # Dataset
│   ├── raw/                     # Fichiers sources bruts
│   │   ├── secure/              # Implémentations sécurisées
│   │   └── vulnerable/          # Implémentations vulnérables
│   ├── dataset.csv              # Dataset annoté (label 0/1)
│   └── dataset_clean.csv        # Dataset nettoyé et équilibré
│
├── src/                         # Code source principal
│   ├── features.py              # Extraction de features (AST + métriques)
│   ├── static_analysis.py       # Détection de patterns dangereux
│   ├── patterns.py              # Règles de détection des vulnérabilités
│   ├── crypto_params.py         # Validation des paramètres cryptographiques
│   ├── scoring.py               # Risk Scoring Engine
│   └── report.py                # Génération des rapports
│
├── ml/                          # Machine Learning
│   ├── train.py                 # Script d'entraînement du modèle
│   ├── evaluate.py              # Évaluation et métriques
│   ├── optimize.py              # Optimisation des hyperparamètres
│   └── model.pkl                # Modèle entraîné (généré après training)
│
├── api.py                       # API FastAPI
├── app.py                       # Interface Streamlit
│
├── notebooks/
│   └── notebook_experimental.ipynb   # Expérimentations ML documentées
│
├── tests/
│   ├── test_cases/              # Fichiers de test (niveaux variés)
│   │   ├── safe_mceliece.py
│   │   ├── vuln_weak_rand.py
│   │   ├── vuln_timing_leak.py
│   │   ├── vuln_weak_params.c
│   │   └── vuln_memory_leak.c
│   ├── test_features.py
│   ├── test_static_analysis.py
│   └── test_api.py
│
├── requirements.txt             # Dépendances Python
├── .gitignore
└── README.md
```

---

## 📊 Dataset

Le dataset est constitué de fichiers de code source labellisés manuellement :

| Label | Valeur | Description |
|---|---|---|
| Sécurisé | `0` | Implémentation correcte, sans vulnérabilité connue |
| Vulnérable | `1` | Implémentation contenant une ou plusieurs failles |

### Sources

- Dépôts GitHub open-source (McEliece, BIKE, HQC, Classic McEliece)
- Code de référence NIST PQC
- Versions intentionnellement fragilisées (construites pour l'entraînement)

### Créer le dataset

```bash
# Collecter et annoter les fichiers
python ml/build_dataset.py --input data/raw/ --output data/dataset.csv

# Nettoyer et équilibrer
python ml/clean_dataset.py --input data/dataset.csv --output data/dataset_clean.csv
```

---

## 🤖 Modèle ML

### Entraîner le modèle

```bash
python ml/train.py --dataset data/dataset_clean.csv --output ml/model.pkl
```

### Évaluer le modèle

```bash
python ml/evaluate.py --model ml/model.pkl --dataset data/dataset_clean.csv
```

Exemple de sortie :

```
=== Résultats d'évaluation ===
Accuracy  : 0.87
Precision : 0.85
Recall    : 0.89
F1-Score  : 0.87
AUC-ROC   : 0.91
```

### Modèles disponibles

| Modèle | Avantage | Commande |
|---|---|---|
| Random Forest | Rapide, interprétable | `--model rf` |
| XGBoost | Précis, gère l'imbalance | `--model xgb` |

---

## 📡 API Reference

### `POST /analyze`

Analyser un fichier de code source.

**Request**

```
Content-Type: multipart/form-data
Body: file (fichier .py ou .c)
```

**Response 200**

```json
{
  "risk_score": float,        // 0.0 à 100.0
  "severity": string,         // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  "vulnerabilities": [
    {
      "type": string,
      "line": int,
      "description": string,
      "severity": string
    }
  ],
  "recommendations": [string],
  "metrics": {
    "loc": int,
    "cyclomatic_complexity": float,
    "num_functions": int
  }
}
```

### `GET /health`

Vérifier l'état de l'API.

**Response 200**

```json
{
  "status": "ok",
  "version": "1.0.0",
  "model_loaded": true
}
```

---

## 🧪 Tests

Lancer la suite de tests :

```bash
# Tous les tests
pytest tests/ -v

# Tests d'un module spécifique
pytest tests/test_static_analysis.py -v

# Avec couverture de code
pytest tests/ --cov=src --cov-report=html
```

### Cas de test inclus

| Fichier | Type | Vulnérabilité |
|---|---|---|
| `safe_mceliece.py` | Sécurisé | Aucune |
| `vuln_weak_rand.py` | Vulnérable | Générateur non-crypto |
| `vuln_timing_leak.py` | Vulnérable | Comparaison non-constante |
| `vuln_weak_params.c` | Vulnérable | Paramètres n, t trop faibles |
| `vuln_memory_leak.c` | Vulnérable | Clé non effacée en mémoire |

---

## 👥 Équipe

| Rôle | Responsabilités |
|---|---|
| **Personne 1 — ML & Data** | Dataset, feature extraction, entraînement modèle, évaluation, optimisation |
| **Personne 2 — Architecture & Sécurité** | Analyse statique, API FastAPI, interface Streamlit, rapport technique |

---

## 📚 Références

- [McEliece, R.J. (1978) — A Public-Key Cryptosystem Based on Algebraic Coding Theory](https://ipnpr.jpl.nasa.gov/progress_report2/42-44/44N.PDF)
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Classic McEliece — Specification](https://classic.mceliece.org/)
- [BIKE — Bit Flipping Key Encapsulation](https://bikesuite.org/)
- [HQC — Hamming Quasi-Cyclic](https://pqc-hqc.org/)
- [Scikit-learn Documentation](https://scikit-learn.org/stable/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [tree-sitter — Multi-language Parser](https://tree-sitter.github.io/)

---

## ⚠️ Avertissement

Ce système est un outil d'**aide à la détection** et non un auditeur de sécurité exhaustif. Un score faible ne garantit pas l'absence de toute vulnérabilité. Une revue manuelle par un expert en sécurité cryptographique reste indispensable pour les déploiements en production.

---

*Projet académique — Cryptographie Post-Quantique*
