import os
import shutil

src_dir = "data/secure/mceliece6688128"
dst_dir = "data/vulnerable/mceliece6688128"
os.makedirs(dst_dir, exist_ok=True)

files = [f for f in os.listdir(src_dir) if f.endswith(('.c', '.h'))]

for filename in files:
    src_path = os.path.join(src_dir, filename)
    with open(src_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Mutation 1 - weak_prng
    m1 = "#include <stdlib.h>  /* VULN: added for rand() */\n" + content
    m1 = m1.replace("randombytes(", "/* VULN */ rand(); //")
    name = filename.replace('.c', '_weak_prng.c').replace('.h', '_weak_prng.h')
    with open(os.path.join(dst_dir, name), 'w') as f:
        f.write(m1)

    # Mutation 2 - weak_params
    m2 = content
    m2 = m2.replace("6688128", "64")
    m2 = m2.replace("240832", "32")
    m2 = m2.replace("128", "8")
    m2 = "/* VULN: weak parameters */\n" + m2
    name = filename.replace('.c', '_weak_params.c').replace('.h', '_weak_params.h')
    with open(os.path.join(dst_dir, name), 'w') as f:
        f.write(m2)

    # Mutation 3 - timing_leak
    m3 = "/* VULN: Potential timing side-channel in comparisons */\n" + content
    m3 = m3.replace("crypto_memcmp(", "/* VULN */ memcmp(")
    m3 = m3.replace("verify(", "/* VULN */ memcmp(")
    name = filename.replace('.c', '_timing_leak.c').replace('.h', '_timing_leak.h')
    with open(os.path.join(dst_dir, name), 'w') as f:
        f.write(m3)

    # Mutation 4 - memory_leak
    m4 = "/* VULN: Private key not cleared from memory */\n" + content
    m4 = m4.replace("memset(sk,", "/* VULN: memset removed */ //memset(sk,")
    m4 = m4.replace("memset(ss,", "/* VULN: memset removed */ //memset(ss,")
    name = filename.replace('.c', '_memory_leak.c').replace('.h', '_memory_leak.h')
    with open(os.path.join(dst_dir, name), 'w') as f:
        f.write(m4)

print(f"✅ Mutations créées pour {len(files)} fichiers")
print(f"✅ Total fichiers vulnérables : {len(files) * 4}")