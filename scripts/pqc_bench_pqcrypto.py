import time, statistics, json, warnings
warnings.filterwarnings("ignore")

ITERATIONS = 10
MSG = b"benchmark test message" * 4
results = {}

def bench(fn, iters=ITERATIONS):
    times = []
    for _ in range(iters):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    return {
        "mean_ms":   round(statistics.mean(times), 4),
        "median_ms": round(statistics.median(times), 4),
        "stdev_ms":  round(statistics.stdev(times), 4) if len(times)>1 else 0,
        "min_ms":    round(min(times), 4),
        "max_ms":    round(max(times), 4),
        "ops_sec":   round(1000 / statistics.mean(times), 1),
    }

print("=== pqcrypto benchmark ===")
print("KEMs...")

KEM_MODULES = [
    ("pqcrypto.kem.ml_kem_512",    "ML-KEM-512"),
    ("pqcrypto.kem.ml_kem_768",    "ML-KEM-768"),
    ("pqcrypto.kem.ml_kem_1024",   "ML-KEM-1024"),
    ("pqcrypto.kem.mceliece348864","McEliece348864"),
    ("pqcrypto.kem.mceliece460896","McEliece460896"),
    ("pqcrypto.kem.hqc_128",       "HQC-128"),
    ("pqcrypto.kem.hqc_192",       "HQC-192"),
    ("pqcrypto.kem.hqc_256",       "HQC-256"),
]

for modname, alg in KEM_MODULES:
    try:
        mod = __import__(modname, fromlist=["generate_keypair","encrypt","decrypt"])
        pk, sk = mod.generate_keypair()
        ct, ss = mod.encrypt(pk)
        results[f"{alg}|pqcrypto|keygen"] = {**bench(lambda: mod.generate_keypair()), "type":"KEM","op":"keygen","library":"pqcrypto","algorithm":alg}
        results[f"{alg}|pqcrypto|encaps"] = {**bench(lambda: mod.encrypt(pk)),         "type":"KEM","op":"encaps","library":"pqcrypto","algorithm":alg}
        results[f"{alg}|pqcrypto|decaps"] = {**bench(lambda: mod.decrypt(sk, ct)),     "type":"KEM","op":"decaps","library":"pqcrypto","algorithm":alg}
        print(f"  ✓ {alg}")
    except Exception as e:
        print(f"  ✗ {alg}: {e}")

print("Signatures...")

SIG_MODULES = [
    ("pqcrypto.sign.ml_dsa_44",               "ML-DSA-44"),
    ("pqcrypto.sign.ml_dsa_65",               "ML-DSA-65"),
    ("pqcrypto.sign.ml_dsa_87",               "ML-DSA-87"),
    ("pqcrypto.sign.falcon_512",              "Falcon-512"),
    ("pqcrypto.sign.falcon_1024",             "Falcon-1024"),
    ("pqcrypto.sign.falcon_padded_512",       "Falcon-padded-512"),
    ("pqcrypto.sign.falcon_padded_1024",      "Falcon-padded-1024"),
    ("pqcrypto.sign.sphincs_sha2_128f_simple","SPHINCS-sha2-128f"),
    ("pqcrypto.sign.sphincs_sha2_128s_simple","SPHINCS-sha2-128s"),
    ("pqcrypto.sign.sphincs_sha2_256f_simple","SPHINCS-sha2-256f"),
    ("pqcrypto.sign.sphincs_sha2_256s_simple","SPHINCS-sha2-256s"),
    ("pqcrypto.sign.sphincs_shake_128f_simple","SPHINCS-shake-128f"),
    ("pqcrypto.sign.sphincs_shake_128s_simple","SPHINCS-shake-128s"),
]

for modname, alg in SIG_MODULES:
    try:
        mod = __import__(modname, fromlist=["generate_keypair","sign","verify"])
        pk, sk = mod.generate_keypair()
        signature = mod.sign(sk, MSG)
        results[f"{alg}|pqcrypto|keygen"] = {**bench(lambda: mod.generate_keypair()),          "type":"SIG","op":"keygen","library":"pqcrypto","algorithm":alg}
        results[f"{alg}|pqcrypto|sign"]   = {**bench(lambda: mod.sign(sk, MSG)),               "type":"SIG","op":"sign",  "library":"pqcrypto","algorithm":alg}
        results[f"{alg}|pqcrypto|verify"] = {**bench(lambda: mod.verify(pk, MSG, signature)),  "type":"SIG","op":"verify","library":"pqcrypto","algorithm":alg}
        print(f"  ✓ {alg}")
    except Exception as e:
        print(f"  ✗ {alg}: {e}")

with open("pqcrypto_results.json", "w") as f:
    json.dump(results, f, indent=2)
print(f"\nDone! {len(results)} entries → pqcrypto_results.json")
