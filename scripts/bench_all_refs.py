import subprocess, json, os, tempfile, statistics

ITERATIONS = 20
results = {}

# ── Dilithium official ref ────────────────────────────────────────────────────
DREF = os.path.expanduser("~/dilithium-ref/ref")

def bench_dil_ref(mode):
    pfx = f"pqcrystals_dilithium{mode}_ref"
    src = "\n".join([
        "#include <stdio.h>","#include <time.h>","#include <string.h>","#include <stdint.h>",
        f'#include "api.h"',
        f"#define PK {pfx}_PUBLICKEYBYTES",
        f"#define SK {pfx}_SECRETKEYBYTES",
        f"#define SIG {pfx}_BYTES",
        f"#define ITERS {ITERATIONS}","#define MLEN 88",
        "double ms(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000.0+t.tv_nsec/1e6;}",
        "int main(){",
        "  uint8_t pk[PK],sk[SK],msg[MLEN],sig[SIG+MLEN],msg2[SIG+MLEN];",
        "  size_t slen; memset(msg,0x42,MLEN);",
        "  double t0,kg=0,sg=0,vf=0; int i;",
        f"  {pfx}_keypair(pk,sk);",
        f"  for(i=0;i<ITERS;i++){{t0=ms();{pfx}_keypair(pk,sk);kg+=ms()-t0;}}",
        f"  for(i=0;i<ITERS;i++){{t0=ms();{pfx}_signature(sig,&slen,msg,MLEN,NULL,0,sk);sg+=ms()-t0;}}",
        f"  {pfx}_signature(sig,&slen,msg,MLEN,NULL,0,sk);",
        f"  for(i=0;i<ITERS;i++){{t0=ms();{pfx}_verify(sig,slen,msg,MLEN,NULL,0,pk);vf+=ms()-t0;}}",
        f'  printf("%.6f %.6f %.6f\\n",kg/ITERS,sg/ITERS,vf/ITERS);',
        "  return 0;}",
    ])
    tmpdir = tempfile.mkdtemp()
    sf = os.path.join(tmpdir,"b.c"); bf = os.path.join(tmpdir,"b")
    with open(sf,"w") as f: f.write(src)
    lib  = os.path.join(DREF, f"libpqcrystals_dilithium{mode}_ref.so")
    fips = os.path.join(DREF, "libpqcrystals_fips202_ref.so")
    rand = os.path.join(DREF, "randombytes.c")
    cmd  = ["gcc","-O2","-o",bf,sf,f"-I{DREF}",lib,fips,rand,"-lm"]
    r = subprocess.run(cmd,capture_output=True,text=True)
    if r.returncode!=0: return None, r.stderr[:300]
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = DREF+":"+env.get("LD_LIBRARY_PATH","")
    r2 = subprocess.run([bf],capture_output=True,text=True,env=env,timeout=60)
    if r2.returncode!=0: return None, r2.stderr[:200]
    vals = r2.stdout.strip().split()
    return ([float(v) for v in vals] if len(vals)==3 else None), None

print("=== Dilithium official reference ===")
for mode,label in [("2","Dilithium2"),("3","Dilithium3"),("5","Dilithium5")]:
    try:
        r,err = bench_dil_ref(mode)
        if r:
            results[f"{label}|dilithium-ref|keygen"] = {"mean_ms":round(r[0],4),"type":"SIG","op":"keygen","library":"dilithium-ref","algorithm":label}
            results[f"{label}|dilithium-ref|sign"]   = {"mean_ms":round(r[1],4),"type":"SIG","op":"sign","library":"dilithium-ref","algorithm":label}
            results[f"{label}|dilithium-ref|verify"] = {"mean_ms":round(r[2],4),"type":"SIG","op":"verify","library":"dilithium-ref","algorithm":label}
            print(f"  ✓ {label}  keygen={r[0]:.4f}ms  sign={r[1]:.4f}ms  verify={r[2]:.4f}ms")
        else:
            print(f"  ✗ {label}: {err}")
    except Exception as e: print(f"  ✗ {label}: {e}")

# ── Kyber official ref ────────────────────────────────────────────────────────
KREF = os.path.expanduser("~/kyber-ref/ref")

def bench_kyber_ref(k, label):
    src = "\n".join([
        "#include <stdio.h>","#include <time.h>","#include <stdint.h>",
        f'#include "api.h"',
        f"#define ITERS {ITERATIONS}",
        "double ms(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000.0+t.tv_nsec/1e6;}",
        "int main(){",
        "  uint8_t pk[CRYPTO_PUBLICKEYBYTES],sk[CRYPTO_SECRETKEYBYTES];",
        "  uint8_t ct[CRYPTO_CIPHERTEXTBYTES],ss[CRYPTO_BYTES],ss2[CRYPTO_BYTES];",
        "  double t0,kg=0,en=0,de=0; int i;",
        "  crypto_kem_keypair(pk,sk);",
        f"  for(i=0;i<ITERS;i++){{t0=ms();crypto_kem_keypair(pk,sk);kg+=ms()-t0;}}",
        f"  for(i=0;i<ITERS;i++){{t0=ms();crypto_kem_enc(ct,ss,pk);en+=ms()-t0;}}",
        f"  for(i=0;i<ITERS;i++){{t0=ms();crypto_kem_dec(ss2,ct,sk);de+=ms()-t0;}}",
        f'  printf("%.6f %.6f %.6f\\n",kg/ITERS,en/ITERS,de/ITERS);',
        "  return 0;}",
    ])
    tmpdir = tempfile.mkdtemp()
    sf = os.path.join(tmpdir,"b.c"); bf = os.path.join(tmpdir,"b")
    with open(sf,"w") as f: f.write(src)
    srcs = [os.path.join(KREF,s) for s in
        ["kem.c","indcpa.c","polyvec.c","poly.c","ntt.c","cbd.c","reduce.c",
         "verify.c","fips202.c","symmetric-shake.c","randombytes.c"]]
    cmd = ["gcc","-O3",f"-DKYBER_K={k}","-fomit-frame-pointer",
           "-o",bf,sf]+srcs+[f"-I{KREF}","-lm"]
    r = subprocess.run(cmd,capture_output=True,text=True)
    if r.returncode!=0: return None, r.stderr[:300]
    r2 = subprocess.run([bf],capture_output=True,text=True,timeout=60)
    if r2.returncode!=0: return None, r2.stderr[:200]
    vals = r2.stdout.strip().split()
    return ([float(v) for v in vals] if len(vals)==3 else None), None

print("\n=== Kyber official reference ===")
for k,label in [("2","Kyber512"),("3","Kyber768"),("4","Kyber1024")]:
    try:
        r,err = bench_kyber_ref(k,label)
        if r:
            results[f"{label}|kyber-ref|keygen"] = {"mean_ms":round(r[0],4),"type":"KEM","op":"keygen","library":"kyber-ref","algorithm":label}
            results[f"{label}|kyber-ref|encaps"] = {"mean_ms":round(r[1],4),"type":"KEM","op":"encaps","library":"kyber-ref","algorithm":label}
            results[f"{label}|kyber-ref|decaps"] = {"mean_ms":round(r[2],4),"type":"KEM","op":"decaps","library":"kyber-ref","algorithm":label}
            print(f"  ✓ {label}  keygen={r[0]:.4f}ms  encaps={r[1]:.4f}ms  decaps={r[2]:.4f}ms")
        else:
            print(f"  ✗ {label}: {err}")
    except Exception as e: print(f"  ✗ {label}: {e}")

# ── SPHINCS+ official ref ─────────────────────────────────────────────────────
SREF = os.path.expanduser("~/sphincs-ref/ref")

def bench_sphincs(params, label):
    src = "\n".join([
        "#include <stdio.h>","#include <time.h>","#include <string.h>","#include <stdint.h>",
        f'#include "api.h"',
        f"#define ITERS {ITERATIONS}","#define MLEN 88",
        "double ms(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000.0+t.tv_nsec/1e6;}",
        "int main(){",
        "  uint8_t pk[CRYPTO_PUBLICKEYBYTES],sk[CRYPTO_SECRETKEYBYTES];",
        "  uint8_t msg[MLEN],sig[CRYPTO_BYTES+MLEN],msg2[CRYPTO_BYTES+MLEN];",
        "  unsigned long long slen,mlen2; memset(msg,0x42,MLEN);",
        "  double t0,kg=0,sg=0,vf=0; int i;",
        "  crypto_sign_keypair(pk,sk);",
        f"  for(i=0;i<ITERS;i++){{t0=ms();crypto_sign_keypair(pk,sk);kg+=ms()-t0;}}",
        f"  for(i=0;i<ITERS;i++){{t0=ms();crypto_sign(sig,&slen,msg,MLEN,sk);sg+=ms()-t0;}}",
        "  crypto_sign(sig,&slen,msg,MLEN,sk);",
        f"  for(i=0;i<ITERS;i++){{t0=ms();crypto_sign_open(msg2,&mlen2,sig,slen,pk);vf+=ms()-t0;}}",
        f'  printf("%.6f %.6f %.6f\\n",kg/ITERS,sg/ITERS,vf/ITERS);',
        "  return 0;}",
    ])
    tmpdir = tempfile.mkdtemp()
    sf = os.path.join(tmpdir,"b.c"); bf = os.path.join(tmpdir,"b")
    with open(sf,"w") as f: f.write(src)
    # Determine hash type from params name
    if "sha2" in params: hash_srcs = ["hash_sha2.c","sha2.c"]
    elif "shake" in params: hash_srcs = ["hash_shake.c","fips202.c"]
    else: hash_srcs = ["hash_haraka.c","haraka.c"]
    # thash type
    if "simple" in params or "f" in params: thash = "thash_sha2_simple.c" if "sha2" in params else "thash_shake_simple.c"
    else: thash = "thash_sha2_robust.c" if "sha2" in params else "thash_shake_robust.c"
    srcs = [os.path.join(SREF,s) for s in
        ["address.c","merkle.c","wots.c","wotsx1.c","utils.c","utilsx1.c",
         "fors.c","sign.c","randombytes.c",thash]+hash_srcs]
    srcs = [s for s in srcs if os.path.exists(s)]
    # params.h selection
    params_dir = os.path.join(os.path.dirname(SREF),"ref","params",f"params-{params}.h")
    params_h = os.path.join(SREF,"params",f"params-{params}.h")
    cmd = ["gcc","-O3","-o",bf,sf]+srcs+[f"-I{SREF}",f"-DPARAMS={params}","-lm","-lcrypto"]
    if os.path.exists(params_h):
        cmd += [f"-DPARAMS_HEADER=\"params/params-{params}.h\""]
    r = subprocess.run(cmd,capture_output=True,text=True)
    if r.returncode!=0: return None, r.stderr[:400]
    r2 = subprocess.run([bf],capture_output=True,text=True,timeout=300)
    if r2.returncode!=0: return None, r2.stderr[:200]
    vals = r2.stdout.strip().split()
    return ([float(v) for v in vals] if len(vals)==3 else None), None

print("\n=== SPHINCS+ official reference ===")
sphincs_params = [
    ("sphincs-sha2-128f","SPHINCS-sha2-128f"),
    ("sphincs-sha2-128s","SPHINCS-sha2-128s"),
    ("sphincs-sha2-256f","SPHINCS-sha2-256f"),
    ("sphincs-shake-128f","SPHINCS-shake-128f"),
]
for params,label in sphincs_params:
    try:
        r,err = bench_sphincs(params,label)
        if r:
            results[f"{label}|sphincs-ref|keygen"] = {"mean_ms":round(r[0],4),"type":"SIG","op":"keygen","library":"sphincs-ref","algorithm":label}
            results[f"{label}|sphincs-ref|sign"]   = {"mean_ms":round(r[1],4),"type":"SIG","op":"sign","library":"sphincs-ref","algorithm":label}
            results[f"{label}|sphincs-ref|verify"] = {"mean_ms":round(r[2],4),"type":"SIG","op":"verify","library":"sphincs-ref","algorithm":label}
            print(f"  ✓ {label}  keygen={r[0]:.4f}ms  sign={r[1]:.4f}ms  verify={r[2]:.4f}ms")
        else:
            print(f"  ✗ {label}: {err[:200]}")
    except Exception as e: print(f"  ✗ {label}: {e}")

with open(os.path.expanduser("~/ref_results.json"),"w") as f:
    json.dump(results,f,indent=2)
print(f"\nDone! {len(results)} entries → ref_results.json")
