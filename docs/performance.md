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

## Health while the workspace is busy

Measure authenticated `PING` with 0, 1,000 and 10,000 ordinary files, first idle
and then during a real encrypted upload/download. The separate server profile
explicitly allows 20,000 files and an 8 GiB quota; the original network workload's
32-file limit is not reused. All files are synthetic and each case owns a
bounded subprocess group. TLS validation and Basic Auth are required.

```console
python tools/health_load_smoke.py --profile quick --output health.json
python tools/health_load_smoke.py --profile weekly --output health-baseline.json
python tools/health_load_smoke.py --profile weekly --baseline health-baseline.json --output health.json
```

Quick uses 20 PING attempts per phase and 16 MiB plus one byte transfers; weekly
uses 100 attempts and 64 MiB plus one byte transfers. The load repeats complete
transfers sequentially until sampling finishes and deletes only those synthetic
files. PING attempts are never retried: status counts, timeouts and transport
failures remain visible. Successful-ready latency is separate from all-attempt
latency; 429/503 responses are reported as throttling, not successful readiness.
A phase with no ready response, malformed health, unexpected status, timeout or
transport failure fails the measurement. Every transfer must pass SHA-256.

Health receipts have their own schema and cannot be compared with `network.json`.
The optional baseline must have the same environment, server settings, profile,
sample count, transfer size and populated-workspace cases. Missing or malformed
baselines produce `baseline_unavailable`; a p95 increase above 25% is advisory.
The scheduled workflow records an initial measurement and a repeat on the same
runner so a comparable current-source baseline exists even when historical
runner hardware has changed. For a low-memory VPS, use a disk-backed `TMPDIR`
such as a dedicated private directory under `/var/tmp`, rather than a small tmpfs.

## Browser memory, storage and reload recovery

The original encrypted browser smoke uses a tiny fixture and an in-memory output
adapter. It remains a functional test and is not a large-file memory benchmark.
The separate Chromium resource tool uses the real application workflow, Web
Crypto, IndexedDB nonce journal, Web Locks and OPFS download cache:

```console
python tools/browser_resource_smoke.py --profile quick --output browser.json
python tools/browser_resource_smoke.py --profile extended --allow-large --output browser-large.json
```

Quick checks a 64 MiB round trip and a separate 64 MiB plus one byte recovery
case. Extended checks 256 MiB plus one byte, 2 GiB, and that recovery case. The
source fixture, output and hashes are streamed with bounded buffers. Keep at
least five times the largest file size plus 256 MiB of temporary free storage
for source, server ciphertext, browser storage and exported output. Browser
profile storage may use a different filesystem; it needs equivalent headroom.

The file-picker adapter returns a real OPFS writable stream, never an array of
all chunks. Receipts explicitly record `syntheticPicker: true` and
`native_picker_verified: false`. Upload recovery pauses after a real chunk
response, reloads the page and reselects the original file and password. Download
recovery deliberately interrupts an output write after caching an authenticated
chunk, reloads, unlocks again and verifies that the cached chunk is not fetched
again. Recovery cases are excluded from timing comparisons. A completed output
must have the expected byte count and SHA-256, and its recovery cache must be
removed.

Linux sampling reports the sum of the Chromium root and descendant process RSS
separately from server RSS. Shared pages can be counted in multiple processes;
this is not exclusive physical memory or JS heap. Unsupported process metrics
are null, never zero. Local browser measurements use secure-context loopback
HTTP; the separate network harness covers authenticated TLS. A disposable
external HTTPS target can be selected with `--target-url`; pass credentials only
through the protected `XFERRY_BROWSER_AUTH_FILE` described in the developer
guide. The tool creates and removes only its own encrypted file. Remote server
RSS is unavailable and reported as null.

The receipt separates the local harness's source/version identity from the
target runtime's `PING` identity captured before and after each case. A changed
target identity fails the case. Current `PING` exposes its runtime version;
target source SHA and build ID remain null when the endpoint does not expose
them. Bind external acceptance to the deployment's separate signed identity and
`status`/`doctor` evidence rather than substituting the harness's local version.

The automatic browser-resource job runs on the default branch alongside network
measurements and retains a separate `browser-resource-measurements` artifact.
Use a real desktop Chrome/Edge session with the native save dialog and at least
256 MiB plus one byte for manual file-picker acceptance. Do not represent an
OPFS adapter run as native-picker or Safari/iOS evidence.
