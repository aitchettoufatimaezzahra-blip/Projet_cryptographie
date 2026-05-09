# Detection de vulnerabilites en cryptographie post-quantique

Ce projet detecte automatiquement des vulnerabilites dans des fichiers sources de cryptographie post-quantique, notamment McEliece, HQC et Classic McEliece 6688128. Il combine une analyse statique basee sur des patterns dangereux avec un modele Random Forest entraine sur des features extraites du code.

## Architecture du projet

```text
Projet_cryptographie-main/
|-- api.py
|-- app.py
|-- requirements.txt
|-- README.md
|-- .gitignore
|-- data/
|   |-- dataset.csv
|   |-- feature_matrix.csv
|   |-- secure/
|   `-- vulnerable/
|-- ml/
|   |-- train.py
|   |-- evaluate.py
|   `-- optimize.py
|-- models/
|   |-- model.pkl
|   `-- feature_cols.pkl
|-- reports/
|-- scripts/
|   |-- generate_mutations.py
|   `-- update_dataset.py
|-- src/
|   |-- features.py
|   |-- static_analysis.py
|   |-- patterns.py
|   |-- crypto_params.py
|   |-- scoring.py
|   `-- report.py
`-- tests/
    |-- test_api.py
    |-- test_features.py
    `-- test_static_analysis.py
```

## Prerequis et installation

Prerequis :

- Python 3.10 ou superieur
- pip
- Un environnement virtuel Python recommande

Installation :

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Utilisation

Lancer l'API FastAPI :

```bash
python api.py
```

L'API est disponible sur `http://127.0.0.1:8000`. La documentation interactive est disponible sur `http://127.0.0.1:8000/docs`.

Lancer ensuite l'interface Streamlit dans un autre terminal :

```bash
streamlit run app.py
```

Importer un fichier `.c`, `.h` ou `.py`, puis lancer l'analyse. Le resultat contient le score ML, le score statique, le score global, la severite, les vulnerabilites detectees et les metriques du fichier.

## Vulnerabilites detectees

| Nom | Description | Severite |
|---|---|---|
| PRNG faible | Utilisation de generateurs non cryptographiques comme `rand`, `srand`, `random.randint` ou `random.getrandbits`. | Critique |
| Timing leak | Comparaisons non constant-time comme `memcmp`, `strcmp`, `strncmp` ou `==` en Python. | Critique |
| Memory leak | Cle privee ou donnees sensibles non effacees apres usage, par exemple `memset` commente ou supprime. | Elevee |
| Parametres faibles | Valeurs cryptographiques inferieures aux seuils minimaux attendus pour `N`, `K`, `T`, `n`, `k` ou `t`. | Elevee |

## Schemas cryptographiques supportes

Le projet cible les implementations de cryptographie basee sur les codes correcteurs :

- McEliece
- HQC
- Classic McEliece 6688128

Les parametres de reference sont centralises dans `src/crypto_params.py`.

## Performances du modele

| Metrique | Valeur |
|---|---:|
| F1-score | 0.92 |
| AUC-ROC | 0.86 |
| Dataset | 585 fichiers |
| Modele | Random Forest |

## Structure des fichiers

```text
Projet_cryptographie-main/
|-- api.py                         # API FastAPI et endpoint /analyze
|-- app.py                         # Interface Streamlit
|-- requirements.txt               # Dependances Python
|-- README.md                      # Documentation du projet
|-- .gitignore                     # Fichiers ignores par Git
|-- data/
|   |-- dataset.csv                # Liste des fichiers et labels
|   |-- feature_matrix.csv         # Matrice de features generee
|   |-- secure/                    # Fichiers sources consideres securises
|   |   |-- hqc/
|   |   |-- mceliece/
|   |   |-- mceliece6688128/
|   |   `-- python/
|   `-- vulnerable/                # Fichiers sources vulnerables ou mutations
|       |-- hqc/
|       |-- mceliece6688128/
|       `-- python/
|-- ml/
|   |-- train.py                   # Entrainement du modele Random Forest
|   |-- evaluate.py                # Evaluation, cross-validation, feature importance
|   `-- optimize.py                # Optimisation GridSearchCV
|-- models/
|   |-- model.pkl                  # Modele entraine
|   `-- feature_cols.pkl           # Colonnes utilisees par le modele
|-- reports/                       # Rapports JSON generes
|-- scripts/
|   |-- generate_mutations.py      # Generation de variantes vulnerables
|   `-- update_dataset.py          # Mise a jour du dataset
|-- src/
|   |-- features.py                # Extraction de features AST, regex et metriques
|   |-- static_analysis.py         # Detecteurs statiques de vulnerabilites
|   |-- patterns.py                # Regex et fonctions dangereuses
|   |-- crypto_params.py           # Seuils et parametres cryptographiques
|   |-- scoring.py                 # Calcul du score global et severite
|   `-- report.py                  # Generation de rapports JSON et resumes
`-- tests/
    |-- test_api.py
    |-- test_features.py
    `-- test_static_analysis.py
```

## Auteurs et contexte academique

Projet academique de detection de vulnerabilites dans les implementations de cryptographie post-quantique. L'objectif est de proposer une chaine complete d'analyse : extraction de caracteristiques, detection statique, apprentissage automatique, scoring de risque et restitution via API et interface web.
