import sys
sys.path.insert(0, 'src')

from features import extract_features_c, extract_features_py


def test_extract_features_c_secure():
    """Verifie qu'un fichier C securise ne signale pas de PRNG faible."""
    features = extract_features_c("data/secure/mceliece/benes.c")

    assert features["has_weak_prng"] == 0


def test_extract_features_c_vulnerable():
    """Verifie qu'un fichier C vulnerable avec rand() est detecte."""
    features = extract_features_c("data/vulnerable/mceliece/benes_weak_prng.c")

    assert features["has_weak_prng"] == 1


def test_extract_features_py_secure(tmp_path):
    """Verifie qu'un fichier Python propre ne contient aucun drapeau de vulnerabilite."""
    source = tmp_path / "safe.py"
    source.write_text(
        "\n".join([
            "import secrets",
            "import hmac",
            "N = 3488",
            "K = 2720",
            "T = 128",
            "private_key = secrets.token_bytes(32)",
            "public_key = secrets.token_bytes(32)",
            "is_valid = hmac.compare_digest(public_key, public_key)",
            "del private_key",
        ]),
        encoding="utf-8",
    )

    features = extract_features_py(str(source))

    assert features["has_weak_prng"] == 0
    assert features["has_timing_leak"] == 0
    assert features["has_memory_leak"] == 0
    assert features["has_weak_params"] == 0


def test_extract_features_py_vulnerable(tmp_path):
    """Verifie qu'un fichier Python utilisant rand() est marque comme PRNG faible."""
    source = tmp_path / "vulnerable.py"
    source.write_text(
        "\n".join([
            "from random import randint as rand",
            "secret = randint(0, 255)",
        ]),
        encoding="utf-8",
    )

    features = extract_features_py(str(source))

    assert features["has_weak_prng"] == 1


def test_loc_count(tmp_path):
    """Verifie que le nombre de lignes est correctement compte."""
    source = tmp_path / "lines.py"
    source.write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")

    features = extract_features_py(str(source))

    assert features["loc"] == 3


def test_dangerous_func_count(tmp_path):
    """Verifie que le compteur de fonctions dangereuses est correct."""
    source = tmp_path / "dangerous.c"
    source.write_text(
        "\n".join([
            "int main(void) {",
            "    rand();",
            "    srand(1);",
            "    memcmp(\"a\", \"b\", 1);",
            "    return 0;",
            "}",
        ]),
        encoding="utf-8",
    )

    features = extract_features_c(str(source))

    assert features["dangerous_func_count"] == 3
