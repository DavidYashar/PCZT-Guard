# Integrating PCZT Guard

PCZT Guard answers one question for a signer: **is the transaction I am about to sign the
transaction I was shown?** It runs anywhere the signer can run — a Rust wallet, a hardware
wallet daemon, a FROST coordinator, a browser tab.

Nothing below needs a spending key, and nothing below touches the network.

---

## 1. As a library (Rust)

```toml
[dependencies]
pczt-guard-core = { path = "../pczt-guard-core" }   # or a git/path dependency
```

```rust
use pczt_guard_core::{verify, FindingCode, Network, Options, Verdict};

fn should_sign(pczt_bytes: &[u8]) -> bool {
    let options = Options {
        // Reject a PCZT built for another network. Without this, a testnet PCZT is
        // accepted by a mainnet signer.
        expected_network: Some(Network::Main),
        // An output with value and no label is unverifiable by default, because that is
        // exactly what a hidden extra output looks like.
        allow_unlabeled_change: false,
        // A privacy leak does not make a PCZT false, but it is still irreversible.
        strict: false,
    };

    match verify(pczt_bytes, &options) {
        Ok(report) if report.verdict == Verdict::Safe => {
            for payment in &report.payments {
                // show what was verified, not what the PCZT claims
                println!("{:?} {:?} -> {:?}", payment.pool, payment.value, payment.shown);
            }
            println!("fee: {:?} zats", report.fee);
            true
        }
        Ok(report) => {
            for finding in &report.findings {
                eprintln!("{:?} {:?}: {}", finding.severity, finding.code, finding.detail);
            }
            false
        }
        Err(e) => {
            eprintln!("not a PCZT: {e}");
            false
        }
    }
}
```

**Exit early on `ADDRESS_MISMATCH`.** It is the finding that means somebody is lying to the
user, as opposed to a PCZT that merely could not be checked.

```rust
if report.findings.iter().any(|f| f.code == FindingCode::AddressMismatch) {
    // Do not sign. Show the user what they were shown versus what they would pay.
}
```

---

## 2. As a command (any language)

```bash
pczt-guard check payment.pczt || exit 1
```

| Exit code | Verdict | What to do |
|---|---|---|
| 0 | `SAFE` | show `report.payments` to the user, then sign |
| 1 | `UNSAFE` | stop; something in the PCZT is false |
| 2 | `CANNOT VERIFY` | stop, or ask the user to confirm an uncheckable detail |
| 3 | not a PCZT, or bad usage | stop; the reason is on stderr |

Machine-readable form, for a coordinator that wants the detail:

```bash
pczt-guard check payment.pczt --json | jq -r '.verdict, (.payments[] | "\(.value) \(.bound)")'
```

Stdin is supported with `-`, so a coordinator never needs a temp file:

```bash
cat payment.pczt | pczt-guard check - --json
```

---

## 3. In the browser or Node (WebAssembly)

```bash
wasm-pack build crates/pczt-guard-wasm --target web --out-dir ../../web-demo/src/wasm
```

```ts
import init, { verify_pczt } from "./wasm/pczt_guard_wasm.js";

await init();

const report = JSON.parse(
  verify_pczt(bytes, /* expected_network */ "main", /* strict */ false, /* allowUnlabeled */ false),
);

if (report.verdict !== "SAFE") throw new Error(`refusing to sign: ${report.verdict}`);
```

The module is ~1 MB of wasm and needs no network at run time. See `web-demo/` for a complete
page: drag-and-drop, three sample transactions, and the report rendered for a human.

---

## 4. Zallet

Zallet's `pczt_sign` forwards to the `pczt` crate's Signer, which performs no address check
([librustzcash#3155]). Guard belongs immediately before that call:

```rust
// before: sign, trusting user_address
// after:
let report = pczt_guard_core::verify(&pczt_bytes, &Default::default())?;
if report.verdict != pczt_guard_core::Verdict::Safe {
    return Err(anyhow!("PCZT Guard refused this PCZT: {:?}", report.findings));
}
signer.sign_orchard(/* … */)?;
```

The same shape works for `pczt_inspect`, whose documentation already warns that the data is
"not cryptographically verified": Guard can fill that view with addresses that were actually
proven.

## 5. zcash-devtool

`pczt inspect` echoes `user_address` without checking it. A `--verify` flag would be one call
to Guard, then printing `report.payments` with `report.findings` in a table beneath.

## 6. FROST coordinators (Zkool, and any multi-party PCZT builder)

A FROST coordinator is the highest-risk signer of all: several parties sign a PCZT that none
of them built alone. PCZT support across FROST tooling is uneven — Zkool coordinates signing
over PCZTs, while Noir Wallet's adapter documents that it does not expose PCZT signing at all —
so a group that does build PCZTs has no shared check to hand its signers.

```text
coordinator: build PCZT  ->  send to signers
signer i:    PCZT Guard   ->  SAFE?  ->  round 1 signature
coordinator: combine      ->  broadcast
```

Every signer runs the same binary over the same bytes and compares verdicts; a signer that
sees `UNSAFE` aborts the round. Because Guard is deterministic and offline, agreeing on the
verdict needs no extra protocol.

## 7. Hardware wallets

A hardware signer that displays `user_address` should verify it before showing it. The check
is cheap — no pairing, no proof verification: one address decode plus a receiver comparison.
Keystone firmware already does part of this by hand in `rust/apps/zcash/src/pczt/check.rs`;
Guard is the reusable form of the same idea.

---

## 8. What to show the user

The verdict is half the answer; the other half is the payment line.

```text
ironwood 1.00000000 ZEC -> utest1x7d90…hgsckh3d  [verified]
fee      0.00010000 ZEC
```

`[verified]` means the address on screen was proven to contain the receiver the value is
committed to. Anything else — `NOT verified`, or a payment with no label — is a question for
the user, not a confirmation.

**Escape every untrusted field before rendering it.** `user_address` is free text from a file
the signer did not write. Rendered raw into a terminal, `ESC[2K` + `ESC[3A` clears the lines
above and repaints the verdict, so the report can be made to read `SAFE` while it says
`UNSAFE`. Guard reports such a label as `LabelControlCharacters` (UNSAFE) and escapes it
before printing, but a wallet displaying the same field needs its own escaping: this is a
property of the label, not of Guard.

**A note on change.** `zcash_client_backend` sets `user_address` only on outputs that pay
somebody else, so wallet change reaches a signer with value and no address. Guard reports that
as `CANNOT VERIFY` by default, because it is indistinguishable from an attacker's hidden
output. Wallets that cannot supply a viewing key can pass `allow_unlabeled_change`, but the
right fix is to prove change rather than to trust it.

---

## 9. Proving change is yours (`--ufvk`)

`allow_unlabeled_change` is a promise the signer cannot check. Supplying the wallet's own
**Unified Full Viewing Key** replaces the promise with a proof: Guard trial-decrypts every
Ironwood and Orchard output, so an unlabelled output either decrypts (it is this wallet's
change, and its value is now known) or does not (it is paying somebody else, and Guard says
`UNSAFE`).

```bash
pczt-guard check payment.pczt --ufvk uviewtest1...            # repeatable, one per account
pczt-guard check payment.pczt --ufvk-file ufvks.txt           # one per line, # comments
```

A viewing key cannot spend, and it never leaves the process. In Rust:

```rust
let (_, orchard_fvk) = /* the account's Orchard FVK */;
let options = Options {
    ufvks: vec![orchard_fvk],
    ..Options::default()
};
```

Two consequences worth knowing:

* A labelled output that also decrypts is a transfer to another of the signer's own
  addresses. Guard reports it as `Role::SelfTransfer`, because the label alone cannot tell a
  co-signer that the money never leaves.
* The browser build never receives a key: `verify_pczt` passes `Options::default()`, which
  keeps the page safe to run on a machine you do not trust.

## 10. Where the viewing key comes from

`--ufvk` works, but a key on the command line is visible to other local users through
`ps`/`/proc/<pid>/cmdline` and is kept in shell history and CI logs. It cannot spend, but it
reveals every note the wallet receives. **Prefer a file:**

```bash
pczt-guard-signer --mnemonic-file phrase.txt --print-ufvk > ufvks.txt   # derive it once
pczt-guard check payment.pczt --ufvk-file ufvks.txt                     # one per line
```

Guard warns on `--ufvk` and never echoes a key value, even shortened, so a phrase pasted
into the wrong flag cannot leak into a log.

## 12. Verifying what you run

PCZT Guard's whole argument is "trust nothing, verify everything" — so it is fair to ask what
you are trusting when you run *it*. There are two separate questions, and it is worth keeping
them apart.

### Is this binary the code we wrote?

The verdict is produced by whichever binary executes, so the binary itself is part of the
trusted base. Three ways to get one, in descending order of confidence:

1. **Build from source** (recommended):

   ```bash
   git clone <repository> && cd pczt-guard
   cargo build --release --locked        # --locked refuses to resolve anything new
   ```

   The source can be read, the build is reproducible with the pinned toolchain, and
   `Cargo.lock` fixes every transitive version. If you are gating real money on this, this is
   the path to take.

2. **A prebuilt artifact** you download. Without a signature and a published hash, you are
   trusting whoever produced the archive. No such release exists yet — that is listed as
   future work rather than quietly implied to be safe.

3. **The browser demo.** You are trusting the page that serves the `.wasm` as much as the
   `.wasm` itself. Serve it locally from a checkout (`npm run dev`) rather than from a URL you
   do not control.

### Are the ingredients trustworthy?

A Rust build pulls in transitive crates, and a few of them run `build.rs` at compile time,
which executes arbitrary code on the build machine. Real incidents (the `xz` backdoor is the
canonical one) have hidden in exactly that step. Two specifics here:

* **Exact pins.** Every Zcash crate is pinned to one librustzcash release set
  (`pczt =0.10.0-pre.2`, `zcash_keys =0.17.0-pre.2`, …), because Ironwood support currently
  exists only in pre-releases. Pre-releases have had less external review and can change
  behaviour between versions, so the pins are both a correctness measure and a review-scope
  statement: this is the code that was tested.
* **`Cargo.lock` is committed**, so `cargo build --locked` resolves to the exact tree the tests
  ran against.

### What is not there yet

* No signed releases, no reproducible-build attestation, no `cargo auditable` metadata.
* No independent human audit — see the note under the header table in `PCZT-Guard-Design.md`.

None of that is needed to *use* the tool from source, and the runtime properties that
matter — no network, no keys, no telemetry, a small dependency surface compared with a full
wallet — hold regardless of how it was built.

## 13. Verify, then sign, in one step

`pczt-guard-signer` runs the verifier with the key it is about to sign with, and refuses:

* `UNSAFE` → always refused; there is no override for a proven lie.
* `CANNOT VERIFY` → refused unless `--allow-unverified` is passed.
* `--dry-run` → runs the whole check and reports, and signs nothing.
* `--print-ufvk` → derives the account's viewing key from the phrase file, so the offline
  `pczt-guard check --ufvk-file` flow works without any other tool.

```bash
pczt-guard-signer --pczt payment.pczt --mnemonic-file phrase.txt --network test --dry-run
pczt-guard-signer --mnemonic-file phrase.txt --print-ufvk > ufvks.txt
```

---

[librustzcash#3155]: https://github.com/zcash/librustzcash/issues/3155
