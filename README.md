# PCZT Guard

**Check the cheque before you sign it.**

An offline, key-free verifier for Zcash PCZTs (partially created transactions) that catches
address-deception attacks before a signature makes them irreversible.

[![CI](https://github.com/DavidYashar/pczt-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/DavidYashar/pczt-guard/actions/workflows/ci.yml)

```console
$ pczt-guard check payment.pczt
CANNOT VERIFY
  payment.pczt · testnet · tx v6 · ironwood

  ironwood 0.24743750 ZEC → utest1rz4hq0n8yk52jr…0sr4wu0w3rzh  [NOT verified]   (×4)
  ironwood 0.01000000 ZEC → utest1k2puyj62jd96ll…rczdmu2r8nr2  [verified]
  fee      0.00025000 ZEC

  unverified UnlabeledOutput ironwood: output carries 24743750 zats but no user_address, so it cannot be shown to the signer
```

---

## The problem

Zcash lets one program build a transaction and another sign it. The half-finished file is a
**PCZT**, and the split is what makes hardware wallets, multisig and FROST co-signers possible.

A PCZT carries two separate things for every payment:

| Field | Meaning |
|---|---|
| `recipient` | the address the money is cryptographically committed to — unfixable once signed |
| `user_address` | a text label showing the human where it goes |

**Nothing in the official `pczt` library requires them to agree.** The signer checks that the
coins being spent are valid, then signs — without ever comparing the label to the commitment.

So: a compromised wallet, plugin or coordinator changes the commitment to the attacker's
address, recomputes everything, and **leaves the label alone**. Your hardware wallet displays
"Pay Alice 1 ZEC". You approve. Every cryptographic check passes, because the file is *valid* —
it is simply not what it says it is.

Upstream: [librustzcash#3155](https://github.com/zcash/librustzcash/issues/3155).

## What it does

PCZT Guard re-derives every claim the PCZT makes about itself, then compares the result against
what the user is being shown. It needs **no spending key** and makes **no network calls**.

| Answer | Meaning |
|---|---|
| `SAFE` | every claim was re-derived and matched → exit `0` |
| `UNSAFE` | something is provably false → exit `1` |
| `CANNOT VERIFY` | nothing is wrong, but something needed for a check is missing → exit `2` |

`CANNOT VERIFY` is never treated as a pass. A tool that says "fine" when it could not look is
worse than no tool.

Exit codes make it a gate:

```bash
pczt-guard check incoming.pczt || exit 1     # sign nothing that isn't SAFE
```

### What it checks

Parse and encoding version · transaction-wide consistency · Ironwood, Orchard, Sapling and
transparent bundles (value commitments, nullifiers, spend-auth randomizers, note commitments) ·
declared-vs-computed value balance · fee against ZIP 317 · **the label against the committed
receiver** · whether the label can even receive in that pool · whether the label belongs to this
network · Merkle witness against the bundle anchor · expiry against a supplied height ·
privacy lints (PL01–PL07).

### Proving change is yours

`zcash_client_backend` labels only *outgoing* payments, so wallet change reaches a signer with
value and no address — indistinguishable from an attacker's hidden output. Supply the wallet's
own **Unified Full Viewing Key** and Guard trial-decrypts every output instead of guessing:

```console
$ pczt-guard check payment.pczt --ufvk-file ufvks.txt
SAFE
  payment.pczt · testnet · tx v6 · ironwood

  ironwood 0.24743750 ZEC → utest1rz4hq0n8yk52jr…0sr4wu0w3rzh  [change, proven]   (×4)
  ironwood 0.01000000 ZEC → utest1k2puyj62jd96ll…rczdmu2r8nr2  [yours, proven]
  fee      0.00025000 ZEC
```

A viewing key cannot spend. An output that *doesn't* decrypt is now **proven** to be paying
somebody else, which turns the weakest verdict into the strongest: `UNSAFE NotOurOutput`.

## Quick start

```bash
git clone https://github.com/DavidYashar/pczt-guard
cd pczt-guard

cargo test --workspace            # 77 tests
cargo run -p pczt-guard-cli -- check fixtures/ironwood-honest.pczt            # SAFE
cargo run -p pczt-guard-cli -- check fixtures/ironwood-address-tampered.pczt  # UNSAFE
```

Regenerate the fixtures (real Ironwood PCZTs, built in-process — no faucet needed):

```bash
cargo run -p xtask -- fixtures fixtures
```

### Use it as a library

```rust
let report = pczt_guard_core::verify(&bytes, &pczt_guard_core::Options::default())?;
if report.verdict != pczt_guard_core::Verdict::Safe {
    return Err("not signing that".into());
}
```

## The browser demo

The same verifier as ~1 MB of WebAssembly (486 KB gzipped). Nothing leaves the tab.

```bash
cd web-demo
npm install
npm run wasm      # build the wasm from crates/pczt-guard-wasm
npm run fixtures  # copy sample PCZTs into public/
npm run dev       # or: npm run build && npx vite preview
```

Deep links make it easy to demo: `/?sample=ironwood-honest` and
`/?sample=ironwood-address-tampered`.

**The web build never receives a viewing key** — `verify_pczt` passes `Options::default()`, so
the "prove change is yours" path exists only in the CLI. That is deliberate: a viewing key
belongs in a process you control, not in a tab.

## What it caught

The attack this tool exists for is reproduced in [`xtask/tests/attack.rs`](xtask/tests/attack.rs):
build a PCZT that pays Mallory while telling the user it pays Alice, then hand it to the
**stock `pczt` Signer**. The signer signs it without complaint — every commitment, nullifier,
randomizer and value balance verifies. The only lie is the label, and the label is what decides
where the money goes.

Guard reports exactly one finding on that file: `AddressMismatch`, `UNSAFE`, exit `1`.

Also verified end-to-end on **Testnet**, on real coins: a real `zcash-devtool` PCZT was checked,
signed, proved, broadcast and mined at height **4,525,306** (txid `e930ce6f…`). The full runbook
is [docs/testnet-e2e.md](docs/testnet-e2e.md).

### Two gaps found upstream

* **`zcash-devtool pczt sign` cannot sign Ironwood spends.** It calls only the Orchard signing
  path, so on any post-NU6.3 transaction it exits `0`, writes a byte-identical file, and
  broadcast later fails with `MissingSpendAuthSig`. [`pczt-guard-signer`](crates/pczt-guard-signer)
  fills the gap and runs the verifier first — `UNSAFE` is always refused, with no override.
* **`DeferredPcztBuilder` leaves `anchor_deferred() == false`** while real spends carry no
  witness, so that flag cannot tell "anchor installed" from "anchor deferred".

## How it was tested

Not claims — commands you can run.

| Evidence | Detail |
|---|---|
| **77 tests**, clippy and fmt clean | `cargo test --workspace` |
| Attack reproduction | the stock signer signs the tampered PCZT; Guard refuses it |
| Differential fuzzing | exhaustive single-byte sweep + 150,000 random mutations per seed, with the oracle *"anything reported SAFE must describe the identical transaction"* |
| Fuzzing result | found **eight** single-byte mutations that were `SAFE` while describing an **empty** transaction; fixed (`EmptyTransaction`, `UnknownNetwork`) and re-run clean |
| Security review | three MEDIUM findings, all fixed with regression tests — see [PCZT-Guard-Design.md](PCZT-Guard-Design.md) §19 |
| Robustness | random, truncated and mutated inputs never panic |

Fuzzing commands, budgets and the measured cost per verification: [docs/fuzzing.md](docs/fuzzing.md).

**Not audited by a human.** It has been reviewed and fuzzed; "reviewed, findings fixed" is the
honest claim, and the design document records every finding rather than only the wins.

## What it does not do

| Limit | Why |
|---|---|
| Cannot prove unlabelled **Sapling** change is yours | Sapling trial decryption is not implemented (deprecated post-NU6.3); such an output stays `CANNOT VERIFY` |
| Does not verify zero-knowledge proofs | `zkproof` is `None` until the *Prover* runs, which is after signing; the chain verifies it |
| Cannot tell whether the anchor exists on-chain | It is offline by design — that is the selling point. `--at-height` covers expiry only |
| Is not a wallet or a signer | `pczt-guard-signer` is a reference signer, written because devtool cannot sign Ironwood |
| Does not check the network unless asked | Pass `--expect-network main\|test`; `coin_type` has no consensus effect |

## Repository layout

```
crates/pczt-guard-core     the verifier: no I/O, no network, no keys
crates/pczt-guard-cli      `pczt-guard` — verdicts, exit codes, JSON, lints
crates/pczt-guard-wasm     the same verifier as WebAssembly
crates/pczt-guard-signer   reference Ironwood signer; verifies before signing
xtask                      builds the fixtures, including the attack
fuzz                       libFuzzer harness + seeded corpus
web-demo                   drag-and-drop browser demo
fixtures                   real Ironwood PCZTs used by tests and demos
docs                       integration guide, testnet runbook, fuzzing notes
```

### A note for security scanners

`fixtures/` and the test suites deliberately contain **key material derived from fixed seeds**
(`[7; 32]`, `[9; 32]`, `[11; 32]`) so tests are reproducible, and
[`text.rs`](crates/pczt-guard-core/src/text.rs) contains the canonical BIP-39 test vector
(`abandon ability able …`). Neither is a secret and neither can spend anything.

## Documentation

* [PCZT-Guard-Design.md](PCZT-Guard-Design.md) — problem, threat model, architecture, and a
  record of every verification finding (§14, §19, §10)
* [docs/integration-guide.md](docs/integration-guide.md) — Zallet, devtool, FROST coordinators,
  hardware wallets, and how to verify what you run (§12)
* [docs/testnet-e2e.md](docs/testnet-e2e.md) — the end-to-end runbook, as executed
* [docs/fuzzing.md](docs/fuzzing.md) — both harnesses and their budgets
* [docs/upstream-3155-proposal.md](docs/upstream-3155-proposal.md) — the API upstream should add

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your
option.

Built for [The Zecathon](https://thezecathon.com), Core & Tooling track.
