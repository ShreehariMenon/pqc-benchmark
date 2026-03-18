import json, os
from collections import defaultdict

# Load all results
all_results = {}
files = {
    "liboqs_results.json": "liboqs",
    "pqcrypto_results.json": "pqcrypto",
    "circl_results.json": "circl",
    "bouncycastle_results.json": "bouncycastle",
    "pqclean_results.json": "pqclean",
}

print("=== Loading results ===")
for fname, lib in files.items():
    path = os.path.expanduser(f"~/{fname}")
    if os.path.exists(path):
        with open(path) as f: data = json.load(f)
        all_results.update(data)
        print(f"  ✓ {lib:20s} {len(data)} entries")
    else:
        print(f"  ✗ {lib:20s} not found")

# Save merged
with open(os.path.expanduser("~/all_results.json"), "w") as f:
    json.dump(all_results, f, indent=2)
print(f"\nTotal: {len(all_results)} entries\n")

# Normalize algorithm names for cross-library comparison
NAME_MAP = {
    "ml-kem-512": "ML-KEM-512", "ml-kem-768": "ML-KEM-768", "ml-kem-1024": "ML-KEM-1024",
    "ml-dsa-44":  "ML-DSA-44",  "ml-dsa-65":  "ML-DSA-65",  "ml-dsa-87":  "ML-DSA-87",
    "falcon-512": "Falcon-512", "falcon-1024": "Falcon-1024",
    "falcon-padded-512": "Falcon-padded-512", "falcon-padded-1024": "Falcon-padded-1024",
    "hqc-128": "HQC-128", "hqc-192": "HQC-192", "hqc-256": "HQC-256",
    "mceliece348864": "McEliece348864",
    "sphincs-sha2-128f-simple": "SPHINCS-sha2-128f",
    "sphincs-sha2-128s-simple": "SPHINCS-sha2-128s",
    "sphincs-sha2-256f-simple": "SPHINCS-sha2-256f",
    "sphincs-sha2-256s-simple": "SPHINCS-sha2-256s",
    "sphincs-shake-128f-simple": "SPHINCS-shake-128f",
    "sphincs-shake-128s-simple": "SPHINCS-shake-128s",
}

# Build normalized index: {alg: {op: {lib: ms}}}
index = defaultdict(lambda: defaultdict(dict))
for key, val in all_results.items():
    parts = key.split("|")
    if len(parts) != 3: continue
    alg, lib, op = parts
    alg_norm = NAME_MAP.get(alg, alg)
    index[alg_norm][op][lib] = val["mean_ms"]

# Print comparison tables
LIBS = ["liboqs", "pqcrypto", "circl", "bouncycastle", "pqclean"]
LIB_SHORT = {"liboqs":"liboqs", "pqcrypto":"pqcrypto", "circl":"circl",
             "bouncycastle":"bc", "pqclean":"pqclean"}

def fastest(op_data):
    if not op_data: return "N/A"
    return min(op_data, key=op_data.get)

print("=" * 100)
print("KEM COMPARISON — keygen / encaps / decaps (ms)")
print("=" * 100)
header = f"{'Algorithm':<28} {'Op':<8}" + "".join(f"{LIB_SHORT[l]:>12}" for l in LIBS) + f"{'Fastest':>12}"
print(header)
print("-" * 100)

kem_algs = ["ML-KEM-512","ML-KEM-768","ML-KEM-1024",
            "Kyber512","Kyber768","Kyber1024",
            "HQC-128","HQC-192","HQC-256",
            "McEliece348864","NTRU-HPS-2048-509","NTRU-HPS-2048-677",
            "BIKE-L1","BIKE-L3","FrodoKEM-640-AES","FrodoKEM-976-AES"]

for alg in kem_algs:
    if alg not in index: continue
    for op in ["keygen","encaps","decaps"]:
        if op not in index[alg]: continue
        op_data = index[alg][op]
        row = f"{alg:<28} {op:<8}"
        for lib in LIBS:
            v = op_data.get(lib)
            row += f"{v:>12.4f}" if v else f"{'—':>12}"
        row += f"{fastest(op_data):>12}"
        print(row)
    print()

print("=" * 100)
print("SIGNATURE COMPARISON — keygen / sign / verify (ms)")
print("=" * 100)
print(header)
print("-" * 100)

sig_algs = ["ML-DSA-44","ML-DSA-65","ML-DSA-87",
            "Dilithium2","Dilithium3","Dilithium5",
            "Falcon-512","Falcon-1024",
            "Falcon-padded-512","Falcon-padded-1024",
            "SPHINCS-sha2-128f","SPHINCS-sha2-128s",
            "SPHINCS-sha2-256f","SPHINCS-sha2-256s",
            "SPHINCS-shake-128f","SPHINCS-shake-128s",
            "MAYO-1","MAYO-2"]

for alg in sig_algs:
    if alg not in index: continue
    for op in ["keygen","sign","verify"]:
        if op not in index[alg]: continue
        op_data = index[alg][op]
        row = f"{alg:<28} {op:<8}"
        for lib in LIBS:
            v = op_data.get(lib)
            row += f"{v:>12.4f}" if v else f"{'—':>12}"
        row += f"{fastest(op_data):>12}"
        print(row)
    print()

# Summary: who wins most
print("=" * 100)
print("OVERALL WINNER TALLY")
print("=" * 100)
wins = defaultdict(int)
total = 0
for alg, ops in index.items():
    for op, lib_data in ops.items():
        if len(lib_data) >= 2:
            wins[fastest(lib_data)] += 1
            total += 1
for lib, w in sorted(wins.items(), key=lambda x: -x[1]):
    bar = "█" * w
    print(f"  {lib:20s} {w:3d} wins  {bar}")
print(f"\n  Total comparisons: {total}")
print(f"\nAll results saved → ~/all_results.json")
