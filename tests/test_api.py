import sys
sys.path.insert(0, 'src')
sys.path.insert(0, '.')

from fastapi.testclient import TestClient

from api import app


client = TestClient(app)


def test_health_endpoint():
    """Verifie que l'endpoint de sante retourne un statut OK."""
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_vulnerable_py():
    """Verifie qu'un fichier Python vulnerable obtient un score global eleve."""
    with open("data/vulnerable/python/mceliece_reference_weak_prng.py", "rb") as f:
        response = client.post(
            "/analyze",
            files={"file": ("mceliece_reference_weak_prng.py", f, "text/x-python")},
        )

    assert response.status_code == 200
    assert response.json()["global_score"] > 50


def test_analyze_secure_c():
    """Verifie qu'un fichier C securise obtient un score global faible."""
    with open("data/secure/mceliece/benes.c", "rb") as f:
        response = client.post(
            "/analyze",
            files={"file": ("benes.c", f, "text/x-c")},
        )

    assert response.status_code == 200
    assert response.json()["global_score"] < 50


def test_analyze_returns_required_fields():
    """Verifie que la reponse d'analyse contient tous les champs requis."""
    required_fields = {
        "file",
        "ml_score",
        "static_score",
        "global_score",
        "severity",
        "vulnerabilities",
        "metrics",
    }

    with open("data/vulnerable/python/mceliece_reference_weak_prng.py", "rb") as f:
        response = client.post(
            "/analyze",
            files={"file": ("mceliece_reference_weak_prng.py", f, "text/x-python")},
        )

    assert response.status_code == 200
    assert required_fields.issubset(response.json().keys())


def test_analyze_severity_critical():
    """Verifie qu'un fichier fortement vulnerable est classe Critique."""
    with open("data/vulnerable/python/mceliece_reference_weak_prng.py", "rb") as f:
        response = client.post(
            "/analyze",
            files={"file": ("mceliece_reference_weak_prng.py", f, "text/x-python")},
        )

    assert response.status_code == 200
    assert response.json()["severity"] == "Critique"


def test_invalid_file_type():
    """Verifie qu'un fichier non supporte retourne une erreur controlee."""
    response = client.post(
        "/analyze",
        files={"file": ("invalid.txt", b"hello", "text/plain")},
    )

    assert response.status_code == 400
    assert "non supporte" in response.json()["detail"]
