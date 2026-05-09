import sys
sys.path.insert(0, 'src')

from static_analysis import (
    analyze_file,
    detect_memory_leak,
    detect_timing_leak,
    detect_weak_params,
    detect_weak_rand,
)


def test_detect_weak_prng_c():
    """Verifie la detection de rand() dans du code C."""
    findings = detect_weak_rand("int x = rand();", lang="c")

    assert findings
    assert findings[0]["type"] == "weak_prng"


def test_detect_weak_prng_py():
    """Verifie la detection de random.randint() dans du code Python."""
    findings = detect_weak_rand("import random\nx = random.randint(0, 10)", lang="python")

    assert findings
    assert findings[0]["type"] == "weak_prng"


def test_detect_timing_leak_c():
    """Verifie la detection de memcmp() comme fuite temporelle en C."""
    findings = detect_timing_leak("int ok = memcmp(a, b, 32);", lang="c")

    assert findings
    assert findings[0]["type"] == "timing_leak"


def test_detect_timing_leak_py():
    """Verifie la detection de l'operateur == comme fuite temporelle en Python."""
    findings = detect_timing_leak("if secret == guess:\n    pass", lang="python")

    assert findings
    assert findings[0]["type"] == "timing_leak"


def test_detect_memory_leak_c():
    """Verifie la detection d'un memset commente dans du code C."""
    findings = detect_memory_leak("//memset(sk, 0, sizeof(sk));", lang="c")

    assert findings
    assert findings[0]["type"] == "memory_leak"


def test_detect_weak_params():
    """Verifie la detection de parametres cryptographiques trop faibles."""
    findings = detect_weak_params("#define N 64\n#define K 32\n#define T 4\n", lang="c")

    assert findings
    assert any(finding["type"] == "weak_params" for finding in findings)


def test_secure_file_no_vulns():
    """Verifie qu'un fichier C securise ne retourne aucune vulnerabilite."""
    result = analyze_file("data/secure/mceliece/benes.c")

    assert result["vulnerabilities"] == []


def test_static_score_range():
    """Verifie que le score statique reste entre 0 et 100."""
    result = analyze_file("data/vulnerable/python/mceliece_reference_weak_prng.py")

    assert 0 <= result["static_score"] <= 100
