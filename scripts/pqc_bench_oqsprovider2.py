import subprocess, json, os, tempfile, statistics

ITERATIONS = 20
results = {}
PROV_PATH = os.path.expanduser("~/oqs-provider/_build/lib")
LIBOQS_INC = os.path.expanduser("~/.local/include")
LIBOQS_LIB = os.path.expanduser("~/.local/lib")

# oqs-provider uses liboqs underneath
# We benchmark it by writing a C program that calls OpenSSL EVP APIs
# with the oqs-provider loaded programmatically

src_template_kem = '''
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>

#define ITERS {iters}

double ms() {{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}}

int main() {{
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!prov) {{ fprintf(stderr, "failed to load oqsprovider\\n"); return 1; }}
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");

    double t0, kg=0, en=0, de=0;
    int i;

    for (i = 0; i < ITERS; i++) {{
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "{alg}", NULL);
        EVP_PKEY *pkey = NULL;
        t0 = ms();
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_generate(ctx, &pkey);
        kg += ms() - t0;

        // encaps
        EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        unsigned char ct[8192], ss1[256], ss2[256];
        size_t ct_len=sizeof(ct), ss_len=sizeof(ss1);
        t0 = ms();
        EVP_PKEY_encapsulate_init(ectx, NULL);
        EVP_PKEY_encapsulate(ectx, ct, &ct_len, ss1, &ss_len);
        en += ms() - t0;

        // decaps
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        size_t ss2_len = sizeof(ss2);
        t0 = ms();
        EVP_PKEY_decapsulate_init(dctx, NULL);
        EVP_PKEY_decapsulate(dctx, ss2, &ss2_len, ct, ct_len);
        de += ms() - t0;

        EVP_PKEY_CTX_free(ectx);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
    }}

    printf("%.6f %.6f %.6f\\n", kg/ITERS, en/ITERS, de/ITERS);
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(defprov);
    return 0;
}}
'''

src_template_sig = '''
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#define ITERS {iters}
#define MLEN 88

double ms() {{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}}

int main() {{
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!prov) {{ fprintf(stderr, "failed to load oqsprovider\\n"); return 1; }}
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");

    unsigned char msg[MLEN];
    memset(msg, 0x42, MLEN);
    double t0, kg=0, sg=0, vf=0;
    int i;

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "{alg}", NULL);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_generate(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);

    for (i = 0; i < ITERS; i++) {{
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "{alg}", NULL);
        EVP_PKEY *pk = NULL;
        t0 = ms();
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_generate(ctx, &pk);
        kg += ms() - t0;
        EVP_PKEY_free(pk);
        EVP_PKEY_CTX_free(ctx);
    }}

    unsigned char sig[32768];
    size_t sig_len = sizeof(sig);
    EVP_MD_CTX *sctx = EVP_MD_CTX_new();
    for (i = 0; i < ITERS; i++) {{
        sig_len = sizeof(sig);
        t0 = ms();
        EVP_DigestSignInit_ex(sctx, NULL, NULL, NULL, NULL, pkey, NULL);
        EVP_DigestSign(sctx, sig, &sig_len, msg, MLEN);
        sg += ms() - t0;
    }}
    sig_len = sizeof(sig);
    EVP_DigestSignInit_ex(sctx, NULL, NULL, NULL, NULL, pkey, NULL);
    EVP_DigestSign(sctx, sig, &sig_len, msg, MLEN);

    EVP_MD_CTX *vctx = EVP_MD_CTX_new();
    for (i = 0; i < ITERS; i++) {{
        t0 = ms();
        EVP_DigestVerifyInit_ex(vctx, NULL, NULL, NULL, NULL, pkey, NULL);
        EVP_DigestVerify(vctx, sig, sig_len, msg, MLEN);
        vf += ms() - t0;
    }}

    printf("%.6f %.6f %.6f\\n", kg/ITERS, sg/ITERS, vf/ITERS);
    EVP_MD_CTX_free(sctx);
    EVP_MD_CTX_free(vctx);
    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(defprov);
    return 0;
}}
'''

def find_openssl_headers():
    for p in ["/usr/include/openssl", "/usr/local/include/openssl",
              "/home/User/apps/openssl/include/openssl"]:
        if os.path.exists(p):
            return os.path.dirname(p)
    return "/usr/include"

def compile_run_kem(alg, timeout=60):
    src = src_template_kem.format(alg=alg, iters=ITERATIONS)
    tmpdir = tempfile.mkdtemp()
    src_file = os.path.join(tmpdir, "b.c")
    bin_file = os.path.join(tmpdir, "b")
    with open(src_file, "w") as f: f.write(src)
    inc = find_openssl_headers()
    cmd = ["gcc", "-O2", "-o", bin_file, src_file,
           f"-I{inc}", f"-L{LIBOQS_LIB}",
           "-lssl", "-lcrypto", "-lm", "-Wl,-rpath,/usr/lib/x86_64-linux-gnu"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return None, r.stderr[:200]
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = LIBOQS_LIB + ":/usr/lib/x86_64-linux-gnu:" + env.get("LD_LIBRARY_PATH","")
    env["OPENSSL_MODULES"] = PROV_PATH
    r2 = subprocess.run([bin_file], capture_output=True, text=True, timeout=timeout, env=env)
    if r2.returncode != 0:
        return None, r2.stderr[:200]
    vals = r2.stdout.strip().split()
    return ([float(v) for v in vals] if len(vals)==3 else None), None

def compile_run_sig(alg, timeout=60):
    src = src_template_sig.format(alg=alg, iters=ITERATIONS)
    tmpdir = tempfile.mkdtemp()
    src_file = os.path.join(tmpdir, "b.c")
    bin_file = os.path.join(tmpdir, "b")
    with open(src_file, "w") as f: f.write(src)
    inc = find_openssl_headers()
    cmd = ["gcc", "-O2", "-o", bin_file, src_file,
           f"-I{inc}", f"-L{LIBOQS_LIB}",
           "-lssl", "-lcrypto", "-lm", "-Wl,-rpath,/usr/lib/x86_64-linux-gnu"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return None, r.stderr[:200]
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = LIBOQS_LIB + ":/usr/lib/x86_64-linux-gnu:" + env.get("LD_LIBRARY_PATH","")
    env["OPENSSL_MODULES"] = PROV_PATH
    r2 = subprocess.run([bin_file], capture_output=True, text=True, timeout=timeout, env=env)
    if r2.returncode != 0:
        return None, r2.stderr[:200]
    vals = r2.stdout.strip().split()
    return ([float(v) for v in vals] if len(vals)==3 else None), None

print("=== oqs-provider (OpenSSL EVP) benchmark ===")
print("KEMs...")
KEM_ALGS = [
    ("mlkem512","ML-KEM-512"), ("mlkem768","ML-KEM-768"), ("mlkem1024","ML-KEM-1024"),
    ("kyber512","Kyber512"), ("kyber768","Kyber768"), ("kyber1024","Kyber1024"),
    ("frodo640aes","FrodoKEM-640-AES"), ("frodo976aes","FrodoKEM-976-AES"),
    ("bikel1","BIKE-L1"), ("hqc128","HQC-128"),
]
for oqs_name, label in KEM_ALGS:
    try:
        r, err = compile_run_kem(oqs_name)
        if r:
            results[f"{label}|oqsprovider|keygen"] = {"mean_ms":round(r[0],4),"type":"KEM","op":"keygen","library":"oqsprovider","algorithm":label}
            results[f"{label}|oqsprovider|encaps"]  = {"mean_ms":round(r[1],4),"type":"KEM","op":"encaps","library":"oqsprovider","algorithm":label}
            results[f"{label}|oqsprovider|decaps"]  = {"mean_ms":round(r[2],4),"type":"KEM","op":"decaps","library":"oqsprovider","algorithm":label}
            print(f"  ✓ {label}  keygen={r[0]:.4f}ms  encaps={r[1]:.4f}ms  decaps={r[2]:.4f}ms")
        else:
            print(f"  ✗ {label}: {err}")
    except Exception as e:
        print(f"  ✗ {label}: {e}")

print("Signatures...")
SIG_ALGS = [
    ("mldsa44","ML-DSA-44"), ("mldsa65","ML-DSA-65"), ("mldsa87","ML-DSA-87"),
    ("falcon512","Falcon-512"), ("falcon1024","Falcon-1024"),
    ("falconpadded512","Falcon-padded-512"),
    ("mayo1","MAYO-1"), ("mayo2","MAYO-2"),
]
for oqs_name, label in SIG_ALGS:
    try:
        r, err = compile_run_sig(oqs_name)
        if r:
            results[f"{label}|oqsprovider|keygen"] = {"mean_ms":round(r[0],4),"type":"SIG","op":"keygen","library":"oqsprovider","algorithm":label}
            results[f"{label}|oqsprovider|sign"]   = {"mean_ms":round(r[1],4),"type":"SIG","op":"sign","library":"oqsprovider","algorithm":label}
            results[f"{label}|oqsprovider|verify"] = {"mean_ms":round(r[2],4),"type":"SIG","op":"verify","library":"oqsprovider","algorithm":label}
            print(f"  ✓ {label}  keygen={r[0]:.4f}ms  sign={r[1]:.4f}ms  verify={r[2]:.4f}ms")
        else:
            print(f"  ✗ {label}: {err}")
    except Exception as e:
        print(f"  ✗ {label}: {e}")

with open(os.path.expanduser("~/oqsprovider_results.json"),"w") as f:
    json.dump(results,f,indent=2)
print(f"\nDone! {len(results)} entries → oqsprovider_results.json")
