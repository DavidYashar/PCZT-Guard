# Round 2: closing the gaps found in round 1

Added 21 Oct 2026. Round 1 shipped a verifier that could say "I cannot tell whether this
unlabelled output is your change". Round 2 turned that into a proof, and closed four of the
six limitations listed in the round-1 write-up. This file records what was built, the
evidence, and — for the two that were deliberately not built — why.

## 1. Proving that unlabelled change is yours (`--ufvk`, `--ufvk-file`)

**What it does.** Given the signer's own Unified Full Viewing Key, PCZT Guard trial-decrypts
every Ironwood and Orchard output.

* Decrypts → the note is the signer's, and its value is now *known* rather than assumed, so
  the fee can be computed exactly and the output can be shown as `[change, proven]`.
* Does not decrypt, and carries no `user_address` → proven to be paying somebody else. That
  is the hidden-output attack, and it is now `UNSAFE` instead of "cannot tell".
* Decrypts, but is labelled as a payment to somebody else → the funds never leave the
  wallet. A co-signer who only sees the label cannot notice this; Guard reports
  `SelfPaymentLabeledExternal`.

**Why it is sound.** `orchard::pczt::Action::decrypt_output_with_ivk` re-derives the action's
`cmx` from the decrypted note, so a ciphertext that decrypts cannot have been swapped for a
different note afterwards. The prepared IVK covers both scopes, because wallets use the
internal scope for change and the external one for self-payments.

**Evidence on real data.** The recorded `zcash-devtool` PCZT
(`fixtures/ironwood-devtool-real.pczt`) went from:

```
CANNOT VERIFY
  ironwood 0.24743750 ZEC → (no address)  [NOT verified]   (×4)
  ironwood 0.01000000 ZEC → utest1k2puy…  [verified]
```

to, with the wallet's own viewing key:

```
SAFE
  ironwood 0.24743750 ZEC → utest1rz4hq…  [change, proven]  (×4)
  ironwood 0.01000000 ZEC → utest1k2puy…  [yours, proven]
  fee      0.00025000 ZEC
```

The `[yours, proven]` line is a real finding: `zcash-devtool wallet generate-address` hands
out further addresses of the *same account*, so the "payment" in our end-to-end run never
left the account. Trial decryption is what revealed that.

**What it does not do.** Sapling trial decryption is not implemented (the pool is deprecated
post-NU6.3 and its notes cannot enter Ironwood), so a Sapling output stays `Unknown`
whatever keys are supplied.

## 2. Verify-then-sign

`pczt-guard-signer` now runs the full verifier, with the viewing key it is about to sign
with, before it touches the phrase:

* `UNSAFE` → refuses, always. There is no flag to override a proven lie.
* `CANNOT VERIFY` → refuses unless `--allow-unverified` is passed, because a check that
  could not run is not a check that passed.
* `--dry-run` reports what would be signed, and signs nothing.

This is strictly stronger than either half alone: the key turns "somebody's unlabelled
output" into "my change", so the gate can be strict without breaking real wallet PCZTs.

## 3. Expiry and anchor checks (`--at-height`)

* `--at-height N` compares the PCZT's expiry height against a height the caller knows.
  An expiry at or below it is `UNSAFE` (`Expired`); no expiry at all is `NoExpiry` (info).
* Every spend's Merkle witness is now rooted against the bundle's anchor. A witness that
  leads elsewhere is `UNSAFE` (`AnchorMismatch`) — no proof can be built for it.
* Guard never learns the chain height itself. It is offline by design, so the caller says.

## 4. The labels' network

`user_address` is now checked against the network of the transaction. `zcash_address 0.14`
exposes no network accessor on `ZcashAddress`, so Guard asks the conversion machinery: a
converter that refuses hands the address's network back in `ConversionError`. A mainnet
label on a testnet transaction is `LabelNetworkMismatch` (`UNSAFE`).

This is stricter than before, when a cross-network label only failed the receiver comparison
and produced a less specific message.

## 5. Proofs: reported, not verified — and why

`Bundle::zkproof` is `None` until the **Prover** runs, and the Prover runs *after* the
Signer. At the moment a signer has to decide, there is normally no proof in the file at all.
Verifying one therefore adds nothing to the signer's safety: an invalid proof is rejected by
the chain before it can move funds, and it cannot cause funds to go to the wrong person.

PCZT Guard reports the state instead: `ProofAbsent` (info, with the explanation) when the
bundle is unproven, `ProofUnverified` (cannot-verify) when a proof is present, because Guard
does not verify them. Implementing verification would need the ~50 MB proving parameters or
a slow keygen, which would cost the 1 MB wasm build and the offline single-binary story.

## 6. The v1 encoding: cannot be exercised, and why that is not a gap

`pczt`'s v1 encoder rejects any v6 transaction:

```rust
// The v1 encoding cannot represent V6 or V7 transactions.
if match pczt.global.tx_version { V6_TX_VERSION => true, ... }
```

Every transaction built after NU6.3 is v6, so a v1 PCZT can only describe a pre-upgrade
transaction. Guard reads whichever encoding `Pczt::parse` accepts, and the pipeline takes
`tx_version` from the file rather than assuming one — but no current builder emits v5
transactions, so no realistic v1 fixture can be constructed. A test asserts the boundary
(`the_v1_encoding_cannot_carry_a_post_nu6_3_transaction`) so that it stays visible.

## 7. Two more findings from the new checks

**`dummy_sk`.** `orchard::pczt::Spend` documents that "Signers MUST reject PCZTs that
contain `dummy_sk` values". Every padded bundle legitimately carries them on its zero-value
ZIP 326 dummy spends, so a blanket rule would condemn every honest transaction. Guard flags
a `dummy_sk` only on a spend that *moves value*, which is the case the rule exists for.

**Deferred anchors are not the empty-tree root.** `DeferredPcztBuilder` output sets
`anchor_deferred() == false` while leaving real spends without witnesses and the anchor
materialised from the builder's own tree — so `anchor_deferred` cannot be trusted to tell
"anchor installed" from "anchor deferred". Guard therefore treats an absent witness on a
real spend as information (witnesses are a Prover input, installed by the Updater) and only
calls a *mismatched* witness unsafe.

## 8. Test count and verification

| Suite | Tests |
|---|---|
| `pczt-guard-core` unit (incl. the new text decoder) | 17 |
| `pczt-guard-core` engine | 28 |
| `pczt-guard-core` robustness | 4 |
| `pczt-guard-cli` | 17 |
| `pczt-guard-signer` (gate) | 4 |
| `xtask` attack reproduction | 4 |
| doctest | 1 |
| **Total** | **75** |

`cargo clippy --workspace --all-targets` is clean, `cargo fmt --all` applied, and
`cargo check -p pczt-guard-wasm --target wasm32-unknown-unknown` still succeeds — the
viewing-key path lives in core and is never reachable from the browser build, which passes
`Options::default()` and therefore never holds a key.

## 9. Post-review security fixes

An independent review found three MEDIUM issues in this round's code; all are fixed with
regression tests. See `PCZT-Guard-Design.md` §21 for the full account. The two that mattered:

* **A proven alien output could be signed.** `allow_unlabeled_change` downgraded
  `Ownership::NotOurs` to a warning, and the signer mapped `--allow-unverified` onto that
  same flag — so "proven to pay somebody else" became "SAFE". The flag now softens only
  `Ownership::Unknown`; a proof is never overridable.
* **A crafted label could repaint the terminal report.** `user_address` is untrusted text
  printed next to the verdict, and `ESC[2K`/`ESC[3A` can erase and rewrite it. Control
  characters are now a finding (`LabelControlCharacters`) and are escaped for display.
