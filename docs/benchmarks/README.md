# Benchmarks (M8, spec 14 test 25)

Raw `ekmmock test bench --report` results. They contain no key material (the DEK is synthetic and is never logged). Measured, not estimated.

## Environment

| | |
|---|---|
| Machine | Intel Core i7-9700K, 8 cores / 8 logical CPUs, 32 GB, Windows 10.0.26300, **shared developer machine** (other programs were running) |
| Runtime | .NET SDK 10.0.403, `dotnet publish -c Release` of `EkmMock.Server`, Server GC + concurrent GC |
| Server | `--dev`, TLS 1.3 + mTLS (the `ekmmock certs dev` PKI), EKM on `127.0.0.1:28443`, console on `127.0.0.1:28080`, default limits (64 concurrent, 200 ms deadline), inspector and structured logging on (default settings) |
| Client | `ekmmock test bench` (Release publish) **on the same machine**, loopback; it competes with the server for the 8 CPUs |
| Keys | `aes-key-1` AES-256 (`A256KWP`), `rsa-key-1` RSA-2048, `rsa-key-4096` RSA-4096 (`RSA-OAEP-256`), 32-byte DEK |
| Load | concurrency 16, 5 s warm-up (discarded), 60 s measured, HTTP/1.1 with one kept-alive connection per worker |

## Results (closed loop, concurrency 16, 60 s)

| Operation | Requests | req/s | p50 | p90 | p99 | p99.9 | max | > 250 ms | Spec target (p99) | Met? |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| AES `unwrapkey` A256KWP | 1,813,291 | 30,221 | 0.41 ms | 0.68 ms | **1.56 ms** | 23.4 ms | 327 ms | 16 (0.0009 %) | < 10 ms | yes |
| RSA-2048 `unwrapkey` RSA-OAEP-256 | 562,028 | 9,367 | 1.45 ms | 2.34 ms | **4.32 ms** | 25.0 ms | 340 ms | 16 (0.0028 %) | < 30 ms | yes |
| RSA-4096 `unwrapkey` RSA-OAEP-256 | 113,628 | 1,894 | 8.19 ms | 11.9 ms | **18.7 ms** | 37.6 ms | 171 ms | 0 | < 100 ms | yes |
| `info` | 1,957,493 | 32,625 | 0.37 ms | 0.64 ms | **1.62 ms** | 18.8 ms | 315 ms | 16 (0.0008 %) | < 5 ms | yes |

0 errors in all four runs. **Not met: "0 % over 250 ms" strictly.** In the three runs above 16 requests (0.001 %-0.003 %) took 250-340 ms. They are not random: they come in clusters of all 16 workers at once about every 10 s (the file lists the slow requests with their offset), so they are one stall of the process or the machine, not slow requests. See "Open finding" below.

## Open-loop runs (AES `unwrapkey`, fixed arrival rate, latency from the scheduled start)

A closed loop hides a stall (the workers that would have sent during the stall wait with it). An open loop does not:

| Rate | Requests | p50 | p90 | p99 | p99.9 | max | > 250 ms |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 req/s | 60,000 | 0.23 ms | 0.39 ms | 5.5 ms | 63.7 ms | 116 ms | 0 |
| 5,000 req/s | 300,000 | 0.33 ms | 1.91 ms | 36.4 ms | 60.9 ms | 89 ms | 0 |

So with a stall-aware measurement the AES p99 target of 10 ms is met at 1,000 req/s (5.5 ms) but **not at 5,000 req/s (36 ms)** on this machine, and no request exceeded 250 ms. (A real Managed HSM sends far fewer requests per second than this.)
The open-loop numbers include the client's own timer jitter (Windows, 1 ms timer resolution requested) and its competition with the server for the CPUs, so they are an upper bound for the server.

## What was found and fixed (see DECISIONS "M8: Benchmark")

* `baseline-before-fixes-aes-unwrap-a256kwp-c16-60s.json`: before any fix, 331 req/s, p50 47 ms, p99 101 ms. Cause: every request built an `X509Chain` (12 ms on Windows); now successful verdicts are cached per (certificate, namespace, intermediates) and tied to the namespace trust instance and the validity window.
* The console logger's default queue mode blocked request threads on stdout; now `DropWrite` with a 16,384 line queue (log lines can be dropped under extreme overload).
* The bench tool itself: allocation-free log-linear histogram (<= 0.8 % error), preflight request, schedule never early.

## Open finding: the ~10 s stalls

Every ~10 s all workers see a 100-340 ms stall at 30k req/s (GC pause counters spike at the same cadence). Tried without effect on the stall itself: logging off, inspector ring 100, keystore flush, `TieredPGO=0`, `TieredCompilation=0`, a 256 MB gen0 budget, non-concurrent GC, workstation GC (workstation GC gave a better open-loop p99, 7-13 ms against 22-26 ms at 3,000-5,000 req/s, but a lower closed-loop throughput; Server GC stays because spec 11.1 asks for it),
2 GC heaps. The root cause is not isolated; the client runs on the same 8 CPUs, so a CPU oversubscription effect (all server GC threads must be scheduled together) is the leading suspect. It should be re-measured with the client on a different machine (M9 / the Azure run).
