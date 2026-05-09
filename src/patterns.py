DANGEROUS_FUNCTIONS_C = [
    "rand", "srand", "random", "srandom",
    "memcmp", "strcmp", "strncmp",
    "malloc", "free", "memset"
]

DANGEROUS_FUNCTIONS_PY = [
    "random.randint", "random.random", "random.getrandbits",
    "randint", "randrange"
]

WEAK_PRNG_PATTERNS_C = [
    (r'\brand\s*\(', "Utilisation de rand() - PRNG non cryptographique"),
    (r'\bsrand\s*\(', "Utilisation de srand() - seed previsible"),
    (r'\brandom\s*\(', "Utilisation de random() - PRNG non cryptographique"),
]

WEAK_PRNG_PATTERNS_PY = [
    (r'\brandom\.randint\s*\(', "Utilisation de random.randint() - PRNG non cryptographique"),
    (r'\brandom\.random\s*\(', "Utilisation de random.random() - PRNG non cryptographique"),
    (r'\brandom\.getrandbits\s*\(', "Utilisation de random.getrandbits() - PRNG non cryptographique"),
    (r'\brandint\s*\(', "Utilisation de randint() - PRNG non cryptographique"),
]

TIMING_LEAK_PATTERNS_C = [
    (r'\bmemcmp\s*\(', "memcmp() non constant-time - timing attack possible"),
    (r'\bstrcmp\s*\(', "strcmp() non constant-time - timing attack possible"),
    (r'\bstrncmp\s*\(', "strncmp() non constant-time - timing attack possible"),
]

MEMORY_LEAK_PATTERNS_C = [
    (r'//\s*memset\s*\(', "memset() commente - cle privee non effacee de la memoire"),
    (r'VULN.*memset', "memset() supprime intentionnellement - memory leak"),
]
