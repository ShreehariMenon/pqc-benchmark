# PQC Open Source Library Benchmark 2026

Comprehensive timing analysis of **10 open-source Post-Quantum Cryptography libraries** on the same x86-64 hardware.

## Libraries Benchmarked

| Library | Language | Algorithms | Notes |
|---|---|---|---|
| liboqs | C + Python | 247 | AVX2 optimized, NIST standard |
| pqcrypto | Python | 21 | PQClean wrappers |
| CIRCL | Go | 6 | Cloudflare, fastest encaps |
| Bouncy Castle | Java | 11 | FIPS certified |
| PQClean | C | 35 | Reference implementations |
| oqs-provider | C/OpenSSL | 18 | TLS integration |
| kyber-ref | C | 3 | Official CRYSTALS-Kyber |
| dilithium-ref | C | 3 | Official CRYSTALS-Dilithium |
| sphincs-ref | C | 4 | Official SPHINCS+ |
| wolfSSL | C | 3 | Embedded/IoT focused |

## Results

- **1,053 benchmark entries** across keygen, encaps/sign, decaps/verify
- **38 KEM algorithms** tested
- **209 signature algorithms** tested
- Hardware: x86-64, Ubuntu 22.04
- Date: March 2026

## Key Findings

- **liboqs** wins 35% of comparisons — AVX2 hardware optimizations
- **CIRCL (Go)** fastest for ML-KEM encaps/decaps
- **PQClean** wins code-based algorithms (McEliece, HQC)
- **Bouncy Castle** slowest — 10-50× vs C/Go (JVM overhead)
- **Falcon signing** — liboqs 17× faster than pqcrypto (AVX2 vs portable C)

## Algorithms Covered

### NIST Standards (FIPS 203/204/205)
- ML-KEM-512/768/1024 (FIPS 203)
- ML-DSA-44/65/87 (FIPS 204)
- SLH-DSA / SPHINCS+ (FIPS 205)

### NIST Alternates
- FALCON-512/1024
- NTRU-HPS, NTRU-HRSS
- BIKE-L1/L3/L5
- HQC-128/192/256
- Classic McEliece
- FrodoKEM
- MAYO

## File Structure
```
pqc-benchmark-project/
├── README.md
├── dashboard/
│   └── pqc_final_dashboard.html    ← Interactive web dashboard
├── results/
│   ├── all_results_final.json      ← All 1,053 entries merged
│   ├── liboqs_results.json
│   ├── pqcrypto_results.json
│   ├── circl_results.json
│   ├── bouncycastle_results.json
│   ├── pqclean_results.json
│   ├── oqsprovider_results.json
│   ├── ref_results.json
│   ├── kyber_wolfssl_results.json
│   └── wolfssl_results.json
├── scripts/
│   ├── pqc_bench_liboqs.py         ← liboqs benchmark
│   ├── pqc_bench_pqcrypto.py       ← pqcrypto benchmark
│   ├── pqc_bench_pqclean.py        ← PQClean C benchmark
│   ├── pqc_bench_oqsprovider2.py   ← oqs-provider benchmark
│   ├── bench_all_refs.py           ← Official refs benchmark
│   ├── bench_wolfssl.py            ← wolfSSL benchmark
│   └── pqc_final_compare.py        ← Cross-library comparison
└── install/
    └── SETUP.md                    ← How to reproduce
```

## How to Reproduce

See `install/SETUP.md` for full instructions.

Quick start:
```bash
# Install liboqs
git clone https://github.com/open-quantum-safe/liboqs
cd liboqs && mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=~/.local ..
ninja && ninja install

# Install Python wrapper
pip install liboqs-python pqcrypto --user

# Run benchmark
export LD_LIBRARY_PATH=~/.local/lib:$LD_LIBRARY_PATH
python3 scripts/pqc_bench_liboqs.py
```

## Dashboard

Open `dashboard/pqc_final_dashboard.html` in any browser.
No server required — fully self-contained HTML.

## References

- NIST PQC Standardization: https://csrc.nist.gov/pqcrypto
- Open Quantum Safe: https://openquantumsafe.org
- CRYSTALS-Kyber: https://pq-crystals.org/kyber
- CRYSTALS-Dilithium: https://pq-crystals.org/dilithium
- SPHINCS+: https://sphincs.org
