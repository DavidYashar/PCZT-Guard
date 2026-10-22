# PCZT Guard

**Check the cheque before you sign it.**

An offline, key-free verifier for Zcash PCZTs (partially created transactions). It re-derives
every claim a half-built transaction makes about itself and checks the one thing no signer
checks: that the address shown to the user is the address the money is actually going to.

[![CI](https://github.com/DavidYashar/PCZT-Guard/actions/workflows/ci.yml/badge.svg)](https://github.com/DavidYashar/PCZT-Guard/actions/workflows/ci.yml)

**Try it now, in the browser, with nothing installed:**
**[davidyashar.github.io/PCZT-Guard](https://davidyashar.github.io/PCZT-Guard/?sample=ironwood-address-tampered)**
— that link opens the address-deception attack directly. It is the same verifier as the CLI,
compiled to WebAssembly, and it runs entirely in your tab.

```console
$ pczt-guard check payment.pczt
CANNOT VERIFY
  payment.pczt · testnet · tx v6 · ironwood

  ironwood 0.24743750 ZEC → utest1rz4hq0n8yk52jr…0sr4wu0w3rzh  [NOT verified]   (×4)
  ironwood 0.01000000 ZEC → utest1k2puyj62jd96ll…rczdmu2r8nr2  [verified]
  fee      0.00025000 ZEC

  unverified UnlabeledOutput ironwood: output carries 24743750 zats but no
  user_address, so it cannot be shown to the signer
```

---

## Contents

- [The problem](#the-problem)
- [What it does](#what-it-does)
- [Install](#install)
- [Use](#use)
- [The browser demo](#the-browser-demo)
- [Strengths](#strengths)
- [Weaknesses](#weaknesses)
- [How it was tested](#how-it-was-tested)
- [What it caught](#what-it-caught)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)

---

## The problem

Zcash lets one program build a transaction and another sign it. The half-finished file is a
**PCZT**, and this split is what makes hardware wallets, multisig and FROST co-signing possible.

A PCZT carries two separate things for every payment:

| Field | Meaning |
|---|---|
| `recipient` | the address the value is cryptographically committed to — immutable once signed |
| `user_address` | a text label showing the human where it goes |

**Nothing in the official `pczt` library requires them to agree.** The signer checks that the
coins being spent are valid, then signs — without comparing the label to the commitment.

So: a compromised wallet, plugin, coordinator or file transfer changes the commitment to the
attacker's address, recomputes everything, and **leaves the label alone**. Your hardware wallet
displays "Pay Alice 1 ZEC". You approve. Every cryptographic check passes, because the file
*is* valid — it is simply not what it says it is. On a shielded pool, nobody can see it happen.

Upstream: [librustzcash#3155](https://github.com/zcash/librustzcash/issues/3155).

## What it does

PCZT Guard re-derives what the PCZT claims, then compares the result against what the user is
being shown. It needs **no spending key** and makes **no network calls**, so it runs on an
air-gapped machine, in a browser tab with the Wi-Fi off, or inside a supply chain you do not
control.

### Three answers

| Answer | Meaning | Exit code |
|---|---|---|
| `SAFE` | every claim was re-derived and matched | `0` |
| `UNSAFE` | something is provably false | `1` |
| `CANNOT VERIFY` | nothing is wrong, but something needed for a check is missing | `2` |
| — | the input is not a PCZT, or the command line is wrong | `3` |

`CANNOT VERIFY` is never treated as a pass. A tool that says "fine" when it could not look is
worse than no tool at all. That single decision drives most of the design.

### What is checked

Parse and encoding version · transaction-wide consistency · Ironwood, Orchard, Sapling and
transparent bundles (value commitments, nullifiers, spend-authorisation randomizers, note
commitments) · declared-versus-computed value balance · fee against ZIP 317 · **the label
against the committed receiver** · whether the label can receive in that pool · whether the
label belongs to this network · Merkle witness against the bundle anchor · expiry against a
supplied height · privacy lints (PL01–PL07).

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

A viewing key cannot spend. An output that *does not* decrypt is now **proven** to be paying
somebody else — `UNSAFE NotOurOutput` — which turns the weakest verdict into the strongest.

---

## Install

PCZT Guard is a Rust binary. There is no native mobile app: on iOS you use the
[browser demo](#the-browser-demo). Builds are reproducible from source, and that is the path
recommended for anything that gates a real signature.

Requirements in all cases: **Rust stable, 1.89 or newer**. The repository contains a
`rust-toolchain.toml`, so `rustup` selects and installs the right toolchain automatically.

### Windows (PowerShell)

```powershell
# 1. Rust plus the MSVC linker it needs
winget install Rustlang.Rustup Microsoft.VisualStudio.2022.BuildTools
#    (in the Build Tools installer, tick "Desktop development with C++")
#    open a NEW terminal afterwards so PATH is picked up

# 2. Build and install
git clone https://github.com/DavidYashar/PCZT-Guard.git
cd PCZT-Guard
cargo install --path crates/pczt-guard-cli --locked

# 3. Verify
pczt-guard --version
```

`cargo install` puts `pczt-guard.exe` in `%USERPROFILE%\.cargo\bin`, which rustup already added
to your `PATH`.

Building the WebAssembly module on Windows also needs **LLVM**, because the `secp256k1` C
dependency requires `clang` for the `wasm32` target:

```powershell
winget install LLVM.LLVM
cd web-demo; npm run wasm
```

**Windows notes that cost us time**, so you do not have to rediscover them:

- `>` in PowerShell writes **UTF-16**, not UTF-8. Both binaries sniff BOMs and decode UTF-16, so
  a redirect works — but if you generate files for other tools, use
  `Set-Content -Encoding ascii`.
- Pasting a multi-line command block into PowerShell can collapse the newlines. Every command in
  [docs/testnet-e2e.md](docs/testnet-e2e.md) is therefore a single `;`-separated line.

### Linux

```bash
# Debian / Ubuntu
sudo apt-get install -y build-essential pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # if Rust is not installed
source "$HOME/.cargo/env"

git clone https://github.com/DavidYashar/PCZT-Guard.git
cd PCZT-Guard
cargo install --path crates/pczt-guard-cli --locked
pczt-guard --version
```

This is the easiest platform for the full toolchain: `clang` for the WebAssembly build is a
normal distribution package (`sudo apt-get install clang`), and the coverage-guided fuzzer runs
out of the box.

### macOS

```bash
xcode-select --install              # the linker and system headers
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # if Rust is not installed
source "$HOME/.cargo/env"

git clone https://github.com/DavidYashar/PCZT-Guard.git
cd PCZT-Guard
cargo install --path crates/pczt-guard-cli --locked
pczt-guard --version
```

Apple Silicon and Intel both work; the same commands apply.

### iOS

There is no command line on iOS, so the CLI does not apply. Use the web build instead — it is
the same verifier compiled to WebAssembly and it runs entirely on the device:

1. Serve the demo from a computer on the same network
   (`cd web-demo && npm run dev -- --host`), then open the printed address in Safari; **or**
   host the built `dist/` folder anywhere static.
2. Drop a `.pczt` file into the page (Files app → share → the browser), or tap one of the
   sample buttons.
3. Read the verdict. Nothing is uploaded: the page has no network code and no key material.

Add it to the Home Screen for an app-like shell. The honest caveat from
[Weaknesses](#weaknesses) applies: you are trusting whichever server delivered the page.

### As a library

```bash
cargo add pczt-guard-core        # once published; until then, use a path or git dependency
```

---

## Use

### The CLI as a gate

```bash
pczt-guard check incoming.pczt || exit 1     # sign nothing that is not SAFE
```

Exit codes are the integration point: a signing script that runs this and stops on non-zero
cannot sign a PCZT Guard has doubts about.

### Common invocations

```bash
# The basics
pczt-guard check payment.pczt
pczt-guard check payment.pczt --json                    # machine-readable report
pczt-guard check -  < payment.pczt                      # read from stdin

# Expectations that make the answer stronger
pczt-guard check payment.pczt --expect-network main     # reject a PCZT for another chain
pczt-guard check payment.pczt --at-height 4525306       # refuse an already-expired PCZT

# Proving which outputs are yours
pczt-guard check payment.pczt --ufvk-file ufvks.txt     # one key per line, # comments
pczt-guard check payment.pczt --ufvk uviewtest1...      # inline (warns: it lands in argv)

# Strictness and documentation
pczt-guard check payment.pczt --strict                  # warnings block signing
pczt-guard check payment.pczt --allow-unlabeled-change  # accept outputs nobody could check
pczt-guard lints                                        # list the privacy rules applied
```

`--allow-unlabeled-change` only softens what could not be checked. If a viewing key *proved* an
output is not yours, no flag will rescue it.

### Getting a viewing key

`pczt-guard-signer` derives one from a BIP-39 phrase file, so the offline check needs no other
tool:

```bash
pczt-guard-signer --mnemonic-file phrase.txt --print-ufvk > ufvks.txt
```

### Verify, then sign

`pczt-guard-signer` runs the full verifier with the key it is about to sign with, and refuses:

```bash
pczt-guard-signer --pczt payment.pczt --mnemonic-file phrase.txt --dry-run
pczt-guard-signer --pczt payment.pczt --mnemonic-file phrase.txt --network test --output signed.pczt
```

- `UNSAFE` → always refused. There is **no override for a proven lie.**
- `CANNOT VERIFY` → refused unless you pass `--allow-unverified`.
- The phrase is read from a file, never from an argument, so it cannot land in shell history or
  a process listing.

This signer exists because `zcash-devtool pczt sign` cannot sign Ironwood spends (see
[What it caught](#what-it-caught)).

### As a library

```rust
let report = pczt_guard_core::verify(&bytes, &pczt_guard_core::Options::default())?;
if report.verdict != pczt_guard_core::Verdict::Safe {
    return Err("not signing that".into());
}
for line in &report.payments {
    println!("{:?} {:?} [{:?}]", line.value, line.shown, line.role);
}
```

### Regenerating the fixtures

Real Ironwood PCZTs, built in-process — no faucet, no coins, no network:

```bash
cargo run -p xtask -- fixtures fixtures
```

This includes `ironwood-address-tampered.pczt`: a fully valid transaction that pays an attacker
while the label says otherwise.

To build a single PCZT of a named honesty class — useful for testing a signer, or for a demo —
use `forge`. It prints what it made, so the terminal shows what the file actually claims:

```console
$ cargo run -p xtask -- forge mismatch /tmp/3-mismatch.pczt
kind:       mismatch
expected:   UNSAFE - the label names one address; the value is committed to another
shown:      utest1x7d90s60qlc5pp29l8…hgsckh3d
committed:  utest1tuxnkpkkgj9gapl62q…7ug6nw6a
file:       /tmp/3-mismatch.pczt (3601 bytes)
```

The three classes are `labelled` (SAFE), `unlabelled` (CANNOT VERIFY) and `mismatch` (UNSAFE).
No wallet will produce the third one, which is exactly why it has to be forged.

---

## The browser demo

The same verifier as WebAssembly — **1.01 MB, 486 KB gzipped** — plus 8 KB of JavaScript.

**Hosted:** <https://davidyashar.github.io/PCZT-Guard/> (GitHub Pages, built and deployed by
[`pages.yml`](.github/workflows/pages.yml)). Deep links: `?sample=ironwood-honest` and
`?sample=ironwood-address-tampered`.

To run it yourself:

```bash
cd web-demo
npm install
npm run wasm       # compile crates/pczt-guard-wasm
npm run fixtures   # copy sample PCZTs into public/
npm run dev        # or: npm run build && npx vite preview
```

Deep links make demos and screenshots easy: `/?sample=ironwood-honest` and
`/?sample=ironwood-address-tampered`.

The page has no network code, no telemetry and no key material. It handles drag-and-drop, and it
escapes the untrusted `user_address` label before rendering (that label is attacker-controlled
text — see [docs/integration-guide.md](docs/integration-guide.md) §8).

**The web build never receives a viewing key.** `verify_pczt` passes `Options::default()`, so
"prove change is yours" exists only in the CLI. That is deliberate: a viewing key belongs in a
process you control, not in a tab.

---

## Strengths

- **It closes a real, open, unaddressed gap.** The check it performs is the one described in
  librustzcash#3155; the stock signer performs none of it, and wallet projects have been
  hand-rolling their own variants — separately and unaudited.
- **No keys, no network, no telemetry.** It cannot leak what it never has, and it works on an
  air-gapped machine. That property is what makes it usable in a hardware-wallet or FROST flow.
- **Missing data is never a pass.** `CANNOT VERIFY` is a first-class answer, and it is sticky:
  the tool would rather tell you it could not look than imply it did.
- **It proves ownership, not just consistency.** With a viewing key, an unlabelled output is
  either proven yours or proven somebody else's. That is a proof where other tools offer a flag.
- **The verdict is machine-readable and gated.** Exit codes 0/1/2/3 mean any script can refuse
  to sign, without parsing prose.
- **It has been attacked on purpose.** The failure mode it targets is reproduced as a test, and
  the verifier was then fuzzed and reviewed; the findings are recorded rather than only the wins.
- **Small and dependency-thin.** About 4,600 lines of our own Rust across four crates — over
  1,100 of them tests — with a dependency surface far smaller than a wallet's. That matters,
  because you have to trust the checker too.
- **One engine, three shapes.** The CLI, the browser build and the library are the same core, so
  they cannot drift apart.

## Weaknesses

This list is deliberately longer than the strengths list. It is what you should weigh before
trusting the tool with a signature.

- **Not audited by a human.** It has been reviewed by an AI security pass and fuzzed, and the
  findings were fixed. "Reviewed, findings fixed" is the accurate claim; "audited" is not.
- **A verifier is itself attack surface.** You replace "trust the wallet that built the PCZT"
  with "trust this tool". That is a large reduction — one small auditable checker instead of
  every wallet's PCZT code — but not a reduction to zero.
- **Sapling change is blind.** A viewing key decrypts Ironwood and Orchard only. An unlabelled
  *Sapling* output stays `CANNOT VERIFY` even with a key. Sapling is deprecated after NU6.3, so
  this rarely bites, but it is a real gap.
- **Cannot verify zero-knowledge proofs.** `zkproof` is absent until the Prover runs, which
  happens *after* signing, so there is usually nothing to verify at the moment of decision. The
  chain verifies proofs before a transaction can be mined. Guard reports `ProofAbsent` rather
  than implying coverage.
- **Anchor checks are internal only.** It proves each Merkle witness leads to the bundle's own
  anchor. It cannot know whether that anchor exists on the real chain — a consistent forgery
  passes Guard and is rejected later by the network. That is the price of being offline, and it
  is the right price.
- **No chain state at all.** `--at-height` is caller-supplied; Guard cannot learn the tip. A
  script that forgets to pass it gets no expiry protection.
- **Network checking is opt-in.** `coin_type` has no consensus effect, so Guard does not police
  it unless you pass `--expect-network`.
- **A hosted web page can be swapped by its host.** The wasm you get is the wasm that server
  sent. Build it locally, or verify a published hash, if that matters to you.
- **Pre-release dependencies.** Ironwood support currently exists only in pre-release
  librustzcash crates, pinned exactly. Pre-releases have had less external review and can change
  behaviour between versions.
- **No signed releases yet.** No reproducible-build attestation, no `cargo auditable` metadata.
  Building from source avoids the question entirely, which is why that is the recommended path.
- **The coverage-guided fuzzer is awkward on Windows.** The libFuzzer harness builds everywhere,
  but running it on Windows needs an ASan runtime matching the compiler's LLVM. The
  deterministic harness, which found the real defects, needs nothing but stable Rust.
- **It is not a wallet and not a general signer.** `pczt-guard-signer` is a reference signer
  written to fill a devtool gap; do not treat it as production wallet software.

---

## How it was tested

Not claims — commands you can run.

| Evidence | Detail |
|---|---|
| **77 tests**, `cargo fmt` and `cargo clippy -D warnings` clean | `cargo test --workspace` |
| The attack, reproduced | [`xtask/tests/attack.rs`](xtask/tests/attack.rs) hands the tampered PCZT to the **stock** `pczt` Signer, which signs it; Guard refuses it |
| Real Testnet run | a real `zcash-devtool` PCZT was checked, signed, proved, broadcast and mined at height **4,525,306** (txid `e930ce6f…`) |
| Differential fuzzing | exhaustive single-byte sweep plus 150,000 random mutations per seed, with the oracle *"anything reported SAFE must describe the identical transaction"* |
| Fuzzing result | found **eight** single-byte mutations that reported `SAFE` while describing an **empty** transaction; fixed (`EmptyTransaction`, `UnknownNetwork`) and re-run clean |
| Security review | three MEDIUM findings — including a terminal-escape attack that could repaint `UNSAFE` as `SAFE` — all fixed with regression tests |
| Robustness | random, truncated and mutated inputs never panic |
| Browser | the built page was driven in a real browser and renders the mismatch correctly |

Budgets, commands and the measured cost per verification: [docs/fuzzing.md](docs/fuzzing.md).
Every finding, including the ones we would rather not advertise, is in
[PCZT-Guard-Design.md](PCZT-Guard-Design.md) §19.

## What it caught

**The attack.** Build a PCZT that pays Mallory while telling the user it pays Alice, then hand it
to the stock `pczt` Signer. It signs without complaint — every commitment, nullifier, randomizer
and value balance verifies. The only lie is the label. Guard reports exactly one finding,
`AddressMismatch`, `UNSAFE`, exit `1`.

**A gap in the ecosystem's own tooling.** `zcash-devtool pczt sign` cannot sign Ironwood spends:
it calls only the Orchard signing path, so on any post-NU6.3 transaction it exits `0`, writes a
byte-identical file, and broadcast later fails with `MissingSpendAuthSig`. `pczt-guard-signer`
fills the gap, and completes the Testnet run above.

**A builder bug.** `DeferredPcztBuilder` leaves `anchor_deferred() == false` while real spends
carry no witness, so that flag cannot distinguish "anchor installed" from "anchor deferred".

**Our own bugs, twice.** The security review found that a crafted label could repaint the
terminal report, and that a flag could downgrade a *proven* alien output to a warning. Both were
ours, both are fixed, both have regression tests.

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

- [PCZT-Guard-Design.md](PCZT-Guard-Design.md) — problem, threat model, architecture, and a
  record of every verification finding
- [docs/integration-guide.md](docs/integration-guide.md) — Zallet, devtool, FROST coordinators,
  hardware wallets, untrusted-label rendering, and how to verify what you run
- [docs/testnet-e2e.md](docs/testnet-e2e.md) — the end-to-end runbook, as executed
- [docs/fuzzing.md](docs/fuzzing.md) — both harnesses and their budgets
- [docs/upstream-3155-proposal.md](docs/upstream-3155-proposal.md) — the API upstream should add

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your
option.

Built for [The Zecathon](https://thezecathon.com), Core & Tooling track.
