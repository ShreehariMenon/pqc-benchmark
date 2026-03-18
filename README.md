# 🔐 PQC Open Source Library Benchmark 2026

> A comprehensive performance analysis of 10 open-source Post-Quantum Cryptography libraries on identical x86-64 hardware.

[![Live Dashboard](https://img.shields.io/badge/Live%20Dashboard-View%20Results-blue?style=for-the-badge)](https://shreeharimenon.github.io/pqc-benchmark/dashboard/)
[![Algorithms](https://img.shields.io/badge/Algorithms-247-green?style=for-the-badge)](#-what-was-measured)
[![Entries](https://img.shields.io/badge/Benchmark%20Entries-1053-orange?style=for-the-badge)](#-repository-structure)
[![Libraries](https://img.shields.io/badge/Libraries-10-purple?style=for-the-badge)](#-libraries-benchmarked)



---

## 📊 Live Dashboard

**[→ Open Interactive Dashboard](https://shreeharimenon.github.io/pqc-benchmark/dashboard/)**

The dashboard includes:
- KEM comparison (keygen / encaps / decaps) with log/linear scale toggle
- Signature comparison (sign / keygen / verify) with algorithm family filter
- Heat map — library × algorithm performance matrix
- Security vs Speed scatter plot
- Library profiles with detailed strengths/limitations
- Full searchable data table with CSV export

---

## 🎯 What Was Measured

We benchmarked all **NIST post-quantum standards** and major alternates:

| Standard | Algorithm | Security Levels |
|---|---|---|
| FIPS 203 | ML-KEM (Kyber) | 128 / 192 / 256-bit |
| FIPS 204 | ML-DSA (Dilithium) | 128 / 192 / 256-bit |
| FIPS 205 | SLH-DSA (SPHINCS+) | 128 / 192 / 256-bit |
| Alternate | FALCON | Level 1 / Level 5 |
| Alternate | NTRU-HPS | Level 1 / Level 3 |
| Alternate | BIKE | Level 1 / Level 3 |
| Alternate | HQC | Level 1 / Level 3 / Level 5 |
| Alternate | FrodoKEM | Level 1 / Level 3 |
| Alternate | Classic McEliece | Level 1 |
| New | MAYO | Level 1 |

---

## 📚 Libraries Benchmarked

| Library | Language | Algorithms | Version | Notes |
|---|---|---|---|---|
| [liboqs](https://github.com/open-quantum-safe/liboqs) | C + Python/Go/Java | 247 | 0.15.0 | **Fastest** — AVX2 optimized |
| [pqcrypto](https://github.com/nicowillis/pqcrypto) | Python | 21 | 0.4.0 | Easiest pip install |
| [CIRCL](https://github.com/cloudflare/circl) | Go | 6 | 1.6.3 | **Fastest encaps** — Cloudflare |
| [Bouncy Castle](https://www.bouncycastle.org) | Java | 11 | 1.78 | FIPS certified |
| [PQClean](https://github.com/PQClean/PQClean) | C reference | 35 | latest | Most auditable |
| [oqs-provider](https://github.com/open-quantum-safe/oqs-provider) | C/OpenSSL | 18 | 0.12.0 | TLS 1.3 integration |
| [kyber-ref](https://github.com/pq-crystals/kyber) | C reference | 3 | NIST R3 | Official Kyber ref |
| [dilithium-ref](https://github.com/pq-crystals/dilithium) | C reference | 3 | NIST R3 | Official Dilithium ref |
| [sphincs-ref](https://github.com/sphincs/sphincsplus) | C reference | 4 | NIST R3 | Official SPHINCS+ ref |
| [wolfSSL](https://github.com/wolfSSL/wolfssl) | C embedded | 3 | latest | FIPS 140-3, IoT |

---

## 🔑 Key Findings

### 1. liboqs wins 35% of all comparisons
AVX2 hardware-optimized assembly makes ML-KEM-512 keygen **3.3× faster** than PQClean reference and **10× faster** than pqcrypto.

### 2. CIRCL (Go) is fastest for ML-KEM encapsulation
Cloudflare's Go implementation achieves **94,000 ops/sec** for ML-KEM-512 encapsulation, beating liboqs (61k ops/sec).

### 3. Falcon signing: 17× gap between implementations
| Library | Falcon-512 sign | 
|---|---|
| liboqs (AVX2) | **0.31ms** |
| pqcrypto (portable C) | 5.28ms |
| Bouncy Castle (Java) | 11.2ms |

### 4. Java is 10–50× slower for PQC
Falcon-512 keygen: liboqs 7.8ms vs Bouncy Castle 47.4ms. JVM overhead is unavoidable.

### 5. McEliece: massive keys but fast encapsulation
261KB public key, 166ms keygen — but only **0.07ms encapsulation**. Key size is the real barrier.

---

## 📂 Repository Structure
```
pqc-benchmark/
├── README.md
├── dashboard/
│   └── index.html              ← Self-contained interactive dashboard
├── results/
│   ├── all_results_final.json  ← All 1,053 entries merged
│   ├── liboqs_results.json
│   ├── pqcrypto_results.json
│   ├── circl_results.json
│   ├── bouncycastle_results.json
│   ├── pqclean_results.json
│   ├── oqsprovider_results.json
│   ├── ref_results.json        ← kyber-ref + dilithium-ref + sphincs-ref
│   ├── kyber_wolfssl_results.json
│   └── wolfssl_results.json
├── scripts/
│   ├── bench_liboqs.py
│   ├── bench_pqcrypto.py
│   ├── bench_pqclean.py
│   ├── bench_oqsprovider.py
│   ├── bench_all_refs.py
│   ├── bench_wolfssl.py
│   └── merge_results.py
└── docs/
    ├── SETUP.md                ← How to reproduce benchmarks
    ├── METHODOLOGY.md          ← Timing methodology explained
    └── ALGORITHMS.md           ← Algorithm descriptions
```

---

## 🔬 Methodology

- **Platform:** x86-64, Ubuntu 22.04, Intel Core CPU
- **Iterations:** 20 per operation
- **Timer:** `clock_gettime(CLOCK_MONOTONIC)` — nanosecond precision
- **Metric:** Mean time in milliseconds across all iterations
- **Warmup:** 1 warmup iteration before measurement
- **Optimization:** Libraries compiled with `-O3` and `-fomit-frame-pointer` where applicable

---

## 🚀 How to Reproduce
```bash
# 1. Install liboqs
git clone https://github.com/open-quantum-safe/liboqs
cd liboqs && mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=~/.local ..
ninja && ninja install

# 2. Install Python libraries
pip install liboqs-python pqcrypto --user

# 3. Set environment
export LD_LIBRARY_PATH=~/.local/lib:$LD_LIBRARY_PATH

# 4. Run benchmarks
python3 scripts/bench_liboqs.py
python3 scripts/bench_pqcrypto.py

# 5. Merge all results
python3 scripts/merge_results.py
```

Full instructions: [docs/SETUP.md](docs/SETUP.md)

---

## 📖 References

- [NIST PQC Standardization](https://csrc.nist.gov/pqcrypto)
- [FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 — SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [Open Quantum Safe Project](https://openquantumsafe.org)
- [CRYSTALS-Kyber](https://pq-crystals.org/kyber)
- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium)
- [SPHINCS+](https://sphincs.org)

---

## 📄 License

Benchmark scripts: MIT License  
Algorithm implementations are subject to their respective licenses.

---

*Benchmarked March 2026 · x86-64 · Ubuntu 22.04*
