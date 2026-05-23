# Solo Miner

`solo-miner` is an educational and experimental Bitcoin CPU solo-mining prototype. It focuses on a fast fixed-width `SHA256d` implementation for 80-byte Bitcoin block headers, benchmark repeatability, and safe live-mining plumbing against Bitcoin Core RPC.

This is not expected to be economically competitive with ASIC mining. Its value is in measurement, correctness experiments, and understanding mining internals.

## Build

Install Rust with `rustup`:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup default stable
```

Build the optimized binary:

```bash
cargo build --release
```

This repository includes `.cargo/config.toml` with:

```toml
[build]
rustflags = ["-C", "target-cpu=native"]
```

That is intentional. The hot path uses CPU feature detection, and native code generation matters for benchmark results. The miner can use SHA-NI, AVX512, or scalar fixed-header SHA256d80 depending on what the CPU exposes and what `--init` measures fastest. Release builds also use fat LTO and one codegen unit in `Cargo.toml`.

## Configuration

Copy `config.json.example` to `config.json` or run `--init`, which creates a config if one does not exist.

```json
{
  "initialized": false,
  "wallet_address": "",
  "mining_mode": "template",
  "template_poll_seconds": 5,
  "longpoll": true,
  "show_progress": 10,
  "reserved_threads": 1,
  "rpc_servers": [
    {
      "name": "local",
      "url": "http://127.0.0.1:8332",
      "username": "",
      "password": ""
    }
  ],
  "optimized": null
}
```

Fields:

- `initialized`: set by `--init` after machine tuning.
- `wallet_address`: payout address for the coinbase transaction.
- `mining_mode`: `template` includes Bitcoin Core's transaction list; `empty` mines coinbase-only and claims subsidy only.
- `template_poll_seconds`: fixed-poll fallback interval for stale-work detection.
- `longpoll`: enables `getblocktemplate` longpoll monitoring.
- `show_progress`: `0` disables progress; `N` prints compact status from the controller roughly every N seconds, outside the hash loop. Elapsed time is shown as `Nd hh:mm:ss`.
- `reserved_threads`: logical CPUs left for the OS, controller, RPC, and local `bitcoind` during `--init` defaults.
- `rpc_servers`: failover endpoints. The miner uses the first healthy synced node and submits through failover if needed.
- `optimized`: written by `--init`; includes backend, threads, batch size, interleave, hash rate, and CPU feature summary.

## Commands

```bash
target/release/solo-miner --init
target/release/solo-miner --mine
target/release/solo-miner --benchmark
target/release/solo-miner --scan-benchmark --benchmark-seconds 15 --threads 64 --batch-size 262144 --interleave 8
target/release/solo-miner --work-design-benchmark --benchmark-seconds 15 --threads 64
target/release/solo-miner --real-block-benchmark --threads 64 --nonce-window 5000000 --interleave 8
```

Arguments:

- `--init`: benchmarks available backends plus combinations of thread count, batch size, and interleave, then writes the best result to config.
- `--mine`: starts live mining from `config.json`.
- `--benchmark`: compares library SHA256d, scalar specialized SHA256d80, compression-based SHA256d80, and SHA-NI SHA256d80.
- `--scan-benchmark`: mining-style target scanning with the optimized SHA-NI scanner. This benchmark requires SHA-NI.
- `--work-design-benchmark`: compares shared-header split nonce ranges against per-worker extraNonce/header contexts.
- `--real-block-benchmark`: fetches a confirmed block header from a public API and scans around its historical nonce.
- `--benchmark-seconds N`: benchmark duration. `--init` defaults to 15 seconds per candidate when this is omitted.
- `--threads N`: worker threads. In live mining this overrides config.
- `--batch-size N`: nonces per worker claim/check. In live mining this overrides config.
- `--interleave N`: SHA-NI streams per worker: `1`, `2`, `4`, or `8`.
- `--pin-threads`: pins worker threads to CPU IDs on Linux.
- `--nonce-window N`: real-block benchmark nonce window around the known nonce.
- `--confirmations N`: confirmed block depth used by real-block benchmark.
- `--config PATH`: config path, default `config.json`.

## Init Tuning

`--init` tests:

- backend: scalar always; SHA-NI when the CPU exposes `sha`; AVX512 when the CPU exposes `avx512f`
- interleave: `1`, `2`, `4`, `8`
- batch size: `65536`, `262144`, `1048576`
- thread counts around available logical CPUs minus `reserved_threads`

It writes:

- selected backend
- selected worker count
- selected batch size
- selected interleave width
- measured total and per-thread H/s
- detected CPU features: `sha_ni`, `sse2`, `ssse3`, `sse4.1`, `avx2`, `avx512f`, `avx512vl`
- benchmark timestamp

The default `reserved_threads=1` is deliberate. The OS can schedule controller and RPC work even when all logical CPUs are busy, but leaving one logical CPU free reduces latency for template refresh, submit, logging, and local Bitcoin Core.

## Live Mining

Live mining uses Bitcoin Core RPC:

1. Select a healthy synced RPC endpoint with `getblockchaininfo`.
2. Fetch work with `getblocktemplate {"rules":["segwit"]}`.
3. Build a coinbase transaction paying `wallet_address`.
4. In `template` mode, preserve Core's template transaction order.
5. In `empty` mode, include only coinbase and claim subsidy only.
6. Build the merkle root and 80-byte header with `bitcoin` consensus serialization.
7. Scan nonce space with the selected backend. `--init` benchmarks available backends and writes the fastest choice to config.
8. On a candidate, verify through an independent cold path before `submitblock`.

Stale work is handled by both `getblocktemplate` longpoll and a fixed poll fallback. If the template changes, including a new block height or same-height transaction set refresh, workers stop at batch boundaries and restart from a fresh template. Progress uses one compact status line:

```text
height=4965618 | reward_fee=596 | tx_fee=53216 | total_reward=53812 | ranges_completed=4 | elapsed=0d 00:13:21 | range_hashrate=1.309 GH/s | target=00000000000006b2c00000000000000000000000000000000000000000000000 | bits=1a06b2c0
```

`reward_fee` is the block subsidy, `tx_fee` is the included transaction fee total, and `total_reward` is subsidy plus transaction fees. A height change means a new best tip/template; a same-height fee or reward change means the current template economics changed.

If a fork or reorg occurs, Bitcoin Core chooses the active best chain. The miner follows the active RPC endpoint's `previousblockhash`. If a failover endpoint is needed, the miner fetches fresh work from that endpoint rather than mixing a template from one node with a chain view from another.

## Candidate Verification

Interleaved SHA-NI is fast but more complex than a scalar loop. For safety, a worker-reported nonce is never submitted directly.

The cold path:

- reconstructs the exact block for the candidate extraNonce and nonce
- serializes the header with the `bitcoin` crate
- recomputes `SHA256(SHA256(header))` with the reference path
- confirms the worker hash matches the reference hash
- confirms the hash is `<= target`
- checks the transaction merkle root
- checks the segwit witness commitment when present
- submits the full serialized block hex with `submitblock`

`submitblock` returning JSON `null` means accepted by that node. Any non-null string is reported as a rejection reason.

When a candidate block is found and submitted, the miner appends a record to `mined.json`. The record includes block height, hash, nonce, extraNonce, template economics, submit result, runtime mining settings, and the full config used for that run. Treat this file as sensitive if your config contains RPC credentials.

## SHA256d Optimizations

Implemented optimizations:

- fixed 80-byte header specialization
- precomputed first 64-byte chunk midstate
- fixed padding and length blocks
- nonce write directly into the second header chunk
- x86 SHA-NI compression path
- x86 AVX512 16-lane SHA256d80 path for CPUs without SHA-NI but with AVX512F
- interleaved SHA-NI streams: `1`, `2`, `4`, `8`
- shared-header split nonce ranges, currently better than per-worker extraNonce contexts on tested hardware
- large batch sizes to avoid checking atomics inside every nonce
- controller-side stop/progress handling outside the hot loop
- `target-cpu=native`
- release LTO with one codegen unit

The removed experiment: specialized second SHA compression was tested and reverted because it was slower on the measured machine.

## Mining Math

Bitcoin encodes the proof-of-work threshold as compact `bits`. The expanded target is a 256-bit integer. A header is valid when:

```text
uint256(SHA256(SHA256(header))) <= target
```

For one hash:

```text
p = (target + 1) / 2^256
```

For hashrate `H` hashes/sec over `t` seconds:

```text
P(success by time t) = 1 - (1 - p)^(H*t)
                    ~= 1 - exp(-H*t*p)
expected_time_seconds = 1 / (H*p)
```

Network difficulty is approximately:

```text
difficulty = max_target / current_target
expected_hashes_per_block = difficulty * 2^32
network_hashrate ~= difficulty * 2^32 / 600
```

The 10-minute block interval is an expectation over many independent trials. Individual block intervals follow an exponential distribution, so many blocks under 10 minutes is normal unless analyzed against the expected distribution and changing network hashrate.

## Operational Notes

- Run a fully synced Bitcoin Core node for live mining.
- Use a wallet address matching the RPC chain: mainnet, testnet, signet, or regtest.
- For public test mining, prefer current Bitcoin Core testnet4 with `bitcoind -testnet4` or `chain=testnet4`; the default RPC port is typically `48332`.
- `template` mode can claim transaction fees because it includes the fee-paying transactions.
- `empty` mode cannot claim omitted transaction fees.
- CPU solo mining on mainnet has a vanishingly small probability of finding a block.
- For correctness testing, use regtest or `--real-block-benchmark`.
