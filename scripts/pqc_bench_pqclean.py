import subprocess, json, os, tempfile, re

ITERATIONS = 10
results = {}
PQCLEAN = os.path.expanduser("~/PQClean")
COMMON = os.path.join(PQCLEAN, "common")

def parse_api(clean_dir):
    api_path = os.path.join(clean_dir, "api.h")
    if not os.path.exists(api_path): return None, None
    with open(api_path) as f: content = f.read()
    # Get macro prefix e.g. PQCLEAN_MLKEM512_CLEAN_
    m = re.search(r'#define\s+(PQCLEAN_\w+?)CRYPTO_PUBLICKEYBYTES', content)
    if not m: return None, None
    mpfx = m.group(1)
    # Function prefix is SAME case as macro prefix e.g. PQCLEAN_MLKEM512_CLEAN_
    fpfx = mpfx
    return mpfx, fpfx

def write_kem_src(mpfx, fpfx, iters):
    lines = [
        '#include <stdio.h>',
        '#include <time.h>',
        '#include <stdint.h>',
        '#include "api.h"',
        'double ms(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000.0+t.tv_nsec/1e6;}',
        'int main(){',
        f'  uint8_t pk[{mpfx}CRYPTO_PUBLICKEYBYTES];',
        f'  uint8_t sk[{mpfx}CRYPTO_SECRETKEYBYTES];',
        f'  uint8_t ct[{mpfx}CRYPTO_CIPHERTEXTBYTES];',
        f'  uint8_t ss[{mpfx}CRYPTO_BYTES], ss2[{mpfx}CRYPTO_BYTES];',
        '  double t0,kg=0,en=0,de=0; int i;',
        f'  {fpfx}crypto_kem_keypair(pk,sk);',
        f'  for(i=0;i<{iters};i++){{t0=ms();{fpfx}crypto_kem_keypair(pk,sk);kg+=ms()-t0;}}',
        f'  for(i=0;i<{iters};i++){{t0=ms();{fpfx}crypto_kem_enc(ct,ss,pk);en+=ms()-t0;}}',
        f'  for(i=0;i<{iters};i++){{t0=ms();{fpfx}crypto_kem_dec(ss2,ct,sk);de+=ms()-t0;}}',
        f'  printf("%.6f %.6f %.6f\\n",kg/{iters},en/{iters},de/{iters});',
        '  return 0;',
        '}',
    ]
    return '\n'.join(lines)

def write_sig_src(mpfx, fpfx, iters):
    lines = [
        '#include <stdio.h>',
        '#include <time.h>',
        '#include <string.h>',
        '#include <stdint.h>',
        '#include "api.h"',
        'double ms(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000.0+t.tv_nsec/1e6;}',
        'int main(){',
        f'  uint8_t pk[{mpfx}CRYPTO_PUBLICKEYBYTES];',
        f'  uint8_t sk[{mpfx}CRYPTO_SECRETKEYBYTES];',
        '  uint8_t msg[88];',
        f'  uint8_t sig[{mpfx}CRYPTO_BYTES+88], msg2[{mpfx}CRYPTO_BYTES+88];',
        '  unsigned long long slen, mlen2;',
        '  memset(msg,0x42,88);',
        '  double t0,kg=0,sg=0,vf=0; int i;',
        f'  {fpfx}crypto_sign_keypair(pk,sk);',
        f'  for(i=0;i<{iters};i++){{t0=ms();{fpfx}crypto_sign_keypair(pk,sk);kg+=ms()-t0;}}',
        f'  for(i=0;i<{iters};i++){{t0=ms();{fpfx}crypto_sign(sig,&slen,msg,88,sk);sg+=ms()-t0;}}',
        f'  {fpfx}crypto_sign(sig,&slen,msg,88,sk);',
        f'  for(i=0;i<{iters};i++){{t0=ms();{fpfx}crypto_sign_open(msg2,&mlen2,sig,slen,pk);vf+=ms()-t0;}}',
        f'  printf("%.6f %.6f %.6f\\n",kg/{iters},sg/{iters},vf/{iters});',
        '  return 0;',
        '}',
    ]
    return '\n'.join(lines)

def compile_run(src, lib_path, clean_dir, timeout=120):
    tmpdir = tempfile.mkdtemp()
    src_file = os.path.join(tmpdir, "b.c")
    bin_file = os.path.join(tmpdir, "b")
    with open(src_file, "w") as f: f.write(src)
    common_srcs = [os.path.join(COMMON,s) for s in
        ["fips202.c","aes.c","sha2.c","randombytes.c","sp800-185.c"]
        if os.path.exists(os.path.join(COMMON,s))]
    cmd = ["gcc","-O2","-o",bin_file,src_file,lib_path,
           f"-I{clean_dir}",f"-I{COMMON}"]+common_srcs+["-lm"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0: return None, r.stderr
    r2 = subprocess.run([bin_file], capture_output=True, text=True, timeout=timeout)
    if r2.returncode != 0: return None, r2.stderr
    vals = r2.stdout.strip().split()
    if len(vals) != 3: return None, "bad output"
    return [float(v) for v in vals], None

def bench_kem(alg, clean_dir):
    libs = [f for f in os.listdir(clean_dir) if f.endswith('.a')]
    if not libs: return None
    lib_path = os.path.join(clean_dir, libs[0])
    mpfx, fpfx = parse_api(clean_dir)
    if not mpfx: return None
    src = write_kem_src(mpfx, fpfx, ITERATIONS)
    r, err = compile_run(src, lib_path, clean_dir)
    return r

def bench_sig(alg, clean_dir):
    libs = [f for f in os.listdir(clean_dir) if f.endswith('.a')]
    if not libs: return None
    lib_path = os.path.join(clean_dir, libs[0])
    mpfx, fpfx = parse_api(clean_dir)
    if not mpfx: return None
    src = write_sig_src(mpfx, fpfx, ITERATIONS)
    r, err = compile_run(src, lib_path, clean_dir)
    return r

print("=== PQClean benchmark ===")
print("KEMs...")
for alg in sorted(os.listdir(os.path.join(PQCLEAN,"crypto_kem"))):
    clean_dir = os.path.join(PQCLEAN,"crypto_kem",alg,"clean")
    if not os.path.isdir(clean_dir): continue
    try:
        r = bench_kem(alg, clean_dir)
        if r:
            results[f"{alg}|pqclean|keygen"] = {"mean_ms":round(r[0],4),"type":"KEM","op":"keygen","library":"pqclean","algorithm":alg}
            results[f"{alg}|pqclean|encaps"]  = {"mean_ms":round(r[1],4),"type":"KEM","op":"encaps","library":"pqclean","algorithm":alg}
            results[f"{alg}|pqclean|decaps"]  = {"mean_ms":round(r[2],4),"type":"KEM","op":"decaps","library":"pqclean","algorithm":alg}
            print(f"  ✓ {alg}  keygen={r[0]:.4f}ms  encaps={r[1]:.4f}ms  decaps={r[2]:.4f}ms")
        else:
            print(f"  ✗ {alg}")
    except Exception as e:
        print(f"  ✗ {alg}: {e}")

print("Signatures...")
for alg in sorted(os.listdir(os.path.join(PQCLEAN,"crypto_sign"))):
    clean_dir = os.path.join(PQCLEAN,"crypto_sign",alg,"clean")
    if not os.path.isdir(clean_dir): continue
    try:
        r = bench_sig(alg, clean_dir)
        if r:
            results[f"{alg}|pqclean|keygen"] = {"mean_ms":round(r[0],4),"type":"SIG","op":"keygen","library":"pqclean","algorithm":alg}
            results[f"{alg}|pqclean|sign"]   = {"mean_ms":round(r[1],4),"type":"SIG","op":"sign","library":"pqclean","algorithm":alg}
            results[f"{alg}|pqclean|verify"] = {"mean_ms":round(r[2],4),"type":"SIG","op":"verify","library":"pqclean","algorithm":alg}
            print(f"  ✓ {alg}  keygen={r[0]:.4f}ms  sign={r[1]:.4f}ms  verify={r[2]:.4f}ms")
        else:
            print(f"  ✗ {alg}")
    except Exception as e:
        print(f"  ✗ {alg}: {e}")

with open("pqclean_results.json","w") as f:
    json.dump(results,f,indent=2)
print(f"\nDone! {len(results)} entries → pqclean_results.json")
