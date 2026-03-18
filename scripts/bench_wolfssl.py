import subprocess, json, os, tempfile

ITERATIONS = 20
results = {}
WOLF_INC = os.path.expanduser("~/wolfssl")
WOLF_LIB = os.path.expanduser("~/wolfssl/build/libwolfssl.so")
WOLF_DIR = os.path.expanduser("~/wolfssl/build")

def compile_run(src, timeout=60):
    tmpdir = tempfile.mkdtemp()
    sf = os.path.join(tmpdir,"b.c"); bf = os.path.join(tmpdir,"b")
    with open(sf,"w") as f: f.write(src)
    cmd = ["gcc","-O2","-o",bf,sf,
           f"-I{WOLF_INC}",f"-I{WOLF_DIR}",
           WOLF_LIB,"-lm",f"-Wl,-rpath,{WOLF_DIR}"]
    r = subprocess.run(cmd,capture_output=True,text=True)
    if r.returncode!=0: return None, r.stderr[:400]
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = WOLF_DIR+":"+env.get("LD_LIBRARY_PATH","")
    r2 = subprocess.run([bf],capture_output=True,text=True,env=env,timeout=timeout)
    if r2.returncode!=0: return None, r2.stderr[:200]
    vals = r2.stdout.strip().split()
    return ([float(v) for v in vals] if len(vals)==3 else None), None

def bench_mlkem(type_enum, label):
    src = "\n".join([
        "#include <stdio.h>","#include <time.h>","#include <stdint.h>",
        "#include <wolfssl/options.h>",
        "#include <wolfssl/wolfcrypt/mlkem.h>",
        "#include <wolfssl/wolfcrypt/random.h>",
        "#include <wolfssl/wolfcrypt/wc_port.h>",
        f"#define ITERS {ITERATIONS}",
        "double ms(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000.0+t.tv_nsec/1e6;}",
        "int main(){",
        f"  MlKemKey key; wc_MlKemKey_Init(&key,{type_enum},NULL,INVALID_DEVID);",
        "  WC_RNG rng; wc_InitRng(&rng);",
        "  word32 ctLen=0,ssLen=0;",
        "  wc_MlKemKey_CipherTextSize(&key,&ctLen);",
        "  wc_MlKemKey_SharedSecretSize(&key,&ssLen);",
        "  unsigned char ct[2000],ss1[64],ss2[64];",
        "  double t0,kg=0,en=0,de=0; int i;",
        "  wc_MlKemKey_MakeKey(&key,&rng);",
        f"  for(i=0;i<ITERS;i++){{t0=ms();wc_MlKemKey_MakeKey(&key,&rng);kg+=ms()-t0;}}",
        f"  for(i=0;i<ITERS;i++){{word32 cl=ctLen,sl=ssLen;t0=ms();wc_MlKemKey_Encapsulate(&key,ct,&cl,ss1,&sl,&rng);en+=ms()-t0;}}",
        "  word32 cl=ctLen,sl=ssLen; wc_MlKemKey_Encapsulate(&key,ct,&cl,ss1,&sl,&rng);",
        f"  for(i=0;i<ITERS;i++){{word32 sl2=ssLen;t0=ms();wc_MlKemKey_Decapsulate(&key,ss2,&sl2,ct,cl);de+=ms()-t0;}}",
        '  printf("%.6f %.6f %.6f\\n",kg/ITERS,en/ITERS,de/ITERS);',
        "  wc_MlKemKey_Free(&key); wc_FreeRng(&rng); return 0;}",
    ])
    return compile_run(src)

def bench_dilithium(level, label):
    src = "\n".join([
        "#include <stdio.h>","#include <time.h>","#include <string.h>","#include <stdint.h>",
        "#include <wolfssl/options.h>",
        "#include <wolfssl/wolfcrypt/dilithium.h>",
        "#include <wolfssl/wolfcrypt/random.h>",
        "#include <wolfssl/wolfcrypt/wc_port.h>",
        f"#define ITERS {ITERATIONS}","#define MLEN 88",
        "double ms(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000.0+t.tv_nsec/1e6;}",
        "int main(){",
        "  dilithium_key key; wc_dilithium_init(&key);",
        f"  wc_dilithium_set_level(&key,{level});",
        "  WC_RNG rng; wc_InitRng(&rng);",
        "  byte msg[MLEN]; memset(msg,0x42,MLEN);",
        "  byte sig[5000]; word32 sigLen=5000;",
        "  double t0,kg=0,sg=0,vf=0; int i,res=0;",
        f"  for(i=0;i<ITERS;i++){{t0=ms();wc_dilithium_make_key(&key,&rng);kg+=ms()-t0;}}",
        f"  for(i=0;i<ITERS;i++){{sigLen=5000;t0=ms();wc_dilithium_sign_msg(msg,MLEN,sig,&sigLen,&rng,&key);sg+=ms()-t0;}}",
        "  sigLen=5000; wc_dilithium_sign_msg(msg,MLEN,sig,&sigLen,&rng,&key);",
        f"  for(i=0;i<ITERS;i++){{t0=ms();wc_dilithium_verify_msg(sig,sigLen,msg,MLEN,&res,&key);vf+=ms()-t0;}}",
        '  printf("%.6f %.6f %.6f\\n",kg/ITERS,sg/ITERS,vf/ITERS);',
        "  wc_dilithium_free(&key); wc_FreeRng(&rng); return 0;}",
    ])
    return compile_run(src)

print("=== wolfSSL ML-KEM ===")
for ttype,label in [("WC_ML_KEM_512","ML-KEM-512"),("WC_ML_KEM_768","ML-KEM-768"),("WC_ML_KEM_1024","ML-KEM-1024")]:
    try:
        r,err = bench_mlkem(ttype,label)
        if r:
            results[f"{label}|wolfssl|keygen"] = {"mean_ms":round(r[0],4),"type":"KEM","op":"keygen","library":"wolfssl","algorithm":label}
            results[f"{label}|wolfssl|encaps"] = {"mean_ms":round(r[1],4),"type":"KEM","op":"encaps","library":"wolfssl","algorithm":label}
            results[f"{label}|wolfssl|decaps"] = {"mean_ms":round(r[2],4),"type":"KEM","op":"decaps","library":"wolfssl","algorithm":label}
            print(f"  ✓ {label}  keygen={r[0]:.4f}ms  encaps={r[1]:.4f}ms  decaps={r[2]:.4f}ms")
        else:
            print(f"  ✗ {label}: {err[:200]}")
    except Exception as e: print(f"  ✗ {label}: {e}")

print("\n=== wolfSSL Dilithium ===")
for level,label in [(2,"Dilithium2"),(3,"Dilithium3"),(5,"Dilithium5")]:
    try:
        r,err = bench_dilithium(level,label)
        if r:
            results[f"{label}|wolfssl|keygen"] = {"mean_ms":round(r[0],4),"type":"SIG","op":"keygen","library":"wolfssl","algorithm":label}
            results[f"{label}|wolfssl|sign"]   = {"mean_ms":round(r[1],4),"type":"SIG","op":"sign","library":"wolfssl","algorithm":label}
            results[f"{label}|wolfssl|verify"] = {"mean_ms":round(r[2],4),"type":"SIG","op":"verify","library":"wolfssl","algorithm":label}
            print(f"  ✓ {label}  keygen={r[0]:.4f}ms  sign={r[1]:.4f}ms  verify={r[2]:.4f}ms")
        else:
            print(f"  ✗ {label}: {err[:200]}")
    except Exception as e: print(f"  ✗ {label}: {e}")

with open(os.path.expanduser("~/wolfssl_results.json"),"w") as f:
    json.dump(results,f,indent=2)
print(f"\nDone! {len(results)} entries → wolfssl_results.json")
