# Benchmark Methodology

## Timing Approach
All benchmarks use `clock_gettime(CLOCK_MONOTONIC)` for nanosecond-precision wall-clock timing. This avoids system call overhead from `gettimeofday` and measures actual elapsed time independent of NTP adjustments.

## Iterations
- **C benchmarks:** 20 iterations, 1 warmup
- **Python benchmarks:** 20 iterations  
- **Java benchmarks:** 20 iterations with JVM warmup
- **Go benchmarks:** 20 iterations

## What we measure
```
t0 = clock_gettime()
operation()  ← keygen / encaps / sign / etc.
t1 = clock_gettime()
elapsed = (t1 - t0) in milliseconds
```
We report the **mean** across all iterations.

## Platform
- CPU: Intel Core (x86-64)
- OS: Ubuntu 22.04 LTS
- Compiler: GCC with -O3 -fomit-frame-pointer
- No CPU pinning or frequency scaling control

## Important notes
- Measurements include memory allocation (not just computation)
- AVX2 availability significantly affects liboqs results
- Java results include JIT warmup overhead
- Process-spawning overhead removed by measuring inside single process
