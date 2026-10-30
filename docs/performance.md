# Performance measurements

The network smoke measures authenticated HTTP/TLS transfers using the public
EUF v1 API. It runs a fresh server process and a separate client process for
each case, with temporary synthetic data and a locally trusted test CA. It
does not measure browser Web Crypto, IndexedDB, OPFS or file-picker behavior.

## Quick validation

On Linux, from the contributor environment:

~~~console
python tools/network_transfer_smoke.py --profile quick --output network.json
~~~

The quick profile transfers 16 MiB and 16 MiB plus one byte concurrently. The
short final chunk checks that chunk boundaries do not truncate a file. A
separate recovery case discards a successful chunk acknowledgement, requires
an idempotent retry, restarts the server against the same state, and completes
the upload using the original manifest and resume MACs. This is a lost
acknowledgement simulation, not a claim that a network proxy dropped a packet.

The TLS certificate is verified with strict certificate validation. Basic Auth
uses the normal verification and admission path; the harness also requires an
unauthenticated request to return 401.

## Larger measurements

~~~console
python tools/network_transfer_smoke.py --profile weekly --allow-large \
  --output performance-results/network.json
python -m pytest -q tests/benchmarks \
  --benchmark-json=performance-results/microbenchmarks.json
~~~

The weekly profile measures 256 MiB files at concurrency 1, 2 and 4, then a
single 2 GiB file. It uses at most two upload chunks in flight per file, ten
server workers and a 128 MiB request-body admission budget. Cases run
sequentially and remove their temporary data afterwards; keep at least
2.25 GiB of free temporary storage for the largest case.

Authentication admission can legitimately return 429 under concurrency. The
client retains authentication and retries 429/503 or transient network
failures with a finite attempt budget and Retry-After handling. Retry waits
count towards total elapsed time and throughput. Recovery faults are excluded
from timing comparisons.

Receipts record file SHA-256 values, byte counts, elapsed time, aggregate
round-trip throughput, throttle/retry counts, server baseline and peak RSS,
and client peak RSS. Upload/download request-attempt latency distributions are
separate. p95 needs at least 20 samples and p99 at least 100; smaller samples
produce null rather than an apparently precise high percentile.

Data integrity, successful recovery, bounded process cleanup and the 512 MiB
server RSS growth acceptance target are strict checks. The body admission
budget is not an RSS ceiling. These are test targets; publish measured
capacity claims only with a successful receipt identifying its environment.
Concurrency results are compared with the same concurrency, not with a
linear extrapolation from one transfer.

## CI and comparisons

The normal CI runs the quick network profile once on Linux/Python 3.12. The
separate Performance measurements workflow runs every Monday at 03:00 UTC
and can be dispatched manually on the default branch. It has a 45-minute
limit and retains measurement artifacts for 30 days.

The comparator selects the latest successful completed measurement workflow
on the default branch whose schema, workload, server settings, runner/CPU
identity, Python, OpenSSL and cryptography versions match. It checks the run
identity and source SHA recorded inside the artifact. It never executes or
extracts baseline content. Missing, expired, malformed or incompatible
evidence is reported as baseline_unavailable.

A latency increase above 25%, microbenchmark median increase above 25%, or
throughput drop above 20% produces an advisory summary. Timing warnings
initially do not fail CI or block release. Correctness and memory failures
remain failures. A baseline run ID and source SHA identify each comparison.

To compare two compatible local network receipts:

~~~console
python tools/compare_performance.py --current network.json \
  --baseline previous-network.json --output comparison.json
~~~

The existing in-process encrypted resource smoke remains complementary:
it exercises the server-decrypt path and cannot establish real HTTP/TLS or
browser resource limits. See [encrypted transfers](encrypted-transfers.md)
for that test and the distinction between protocol limits and measured sizes.
