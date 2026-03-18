import oqs, time, statistics, json, warnings
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

# Focus on key algorithms only for comparison
KEM_ALGS = [
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "Kyber512", "Kyber768", "Kyber1024",
    "NTRU-HPS-2048-509", "NTRU-HPS-2048-677",
    "BIKE-L1", "BIKE-L3",
    "HQC-128", "HQC-192",
    "FrodoKEM-640-AES", "FrodoKEM-976-AES",
    "Classic-McEliece-348864",
]

SIG_ALGS = [
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "Falcon-512", "Falcon-1024",
    "Falcon-padded-512", "Falcon-padded-1024",
    "SLH_DSA_PURE_SHA2_128S", "SLH_DSA_PURE_SHA2_128F",
    "SLH_DSA_PURE_SHA2_256S", "SLH_DSA_PURE_SHA2_256F",
    "MAYO-1", "MAYO-2", "MAYO-3",
]

print("=== liboqs benchmark ===")
print("KEMs...")
for alg in KEM_ALGS:
    try:
        kem = oqs.KeyEncapsulation(alg)
        pk = kem.generate_keypair()
        ct, ss = kem.encap_secret(pk)
        results[f"{alg}|liboqs|keygen"] = {**bench(lambda: kem.generate_keypair()), "type":"KEM","op":"keygen","library":"liboqs","algorithm":alg,"pk_bytes":kem.details["length_public_key"],"ct_bytes":kem.details["length_ciphertext"],"nist_level":kem.details["claimed_nist_level"]}
        results[f"{alg}|liboqs|encaps"] = {**bench(lambda: kem.encap_secret(pk)), "type":"KEM","op":"encaps","library":"liboqs","algorithm":alg}
        results[f"{alg}|liboqs|decaps"] = {**bench(lambda: kem.decap_secret(ct)), "type":"KEM","op":"decaps","library":"liboqs","algorithm":alg}
        kem.free()
        print(f"  ✓ {alg}")
    except Exception as e:
        print(f"  ✗ {alg}: {e}")

print("Signatures...")
for alg in SIG_ALGS:
    try:
        sig = oqs.Signature(alg)
        pk = sig.generate_keypair()
        signature = sig.sign(MSG)
        results[f"{alg}|liboqs|keygen"] = {**bench(lambda: sig.generate_keypair()), "type":"SIG","op":"keygen","library":"liboqs","algorithm":alg,"pk_bytes":sig.details["length_public_key"],"sig_bytes":sig.details["length_signature"],"nist_level":sig.details["claimed_nist_level"]}
        results[f"{alg}|liboqs|sign"]   = {**bench(lambda: sig.sign(MSG)), "type":"SIG","op":"sign","library":"liboqs","algorithm":alg}
        results[f"{alg}|liboqs|verify"] = {**bench(lambda: sig.verify(MSG, signature, pk)), "type":"SIG","op":"verify","library":"liboqs","algorithm":alg}
        sig.free()
        print(f"  ✓ {alg}")
    except Exception as e:
        print(f"  ✗ {alg}: {e}")

with open("liboqs_results.json", "w") as f:
    json.dump(results, f, indent=2)
print(f"\nDone! {len(results)} entries → liboqs_results.json")
