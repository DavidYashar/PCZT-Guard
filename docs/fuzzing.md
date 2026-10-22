# Fuzzing PCZT Guard

Two harnesses, answering two different questions. Both are in the repository and both are
opt-in, so the ordinary `cargo test` stays fast.

## 1. Byte-sweep + mutation, with a semantic oracle

`crates/pczt-guard-core/tests/fuzz_differential.rs`

```bash
cargo test --release -p pczt-guard-core --test fuzz_differential -- --ignored --nocapture
```

Environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `PCZT_GUARD_FUZZ_ITERS` | 20000 | random multi-byte mutations per seed |
| `PCZT_GUARD_FUZZ_SEED` | fixed | PRNG seed, so a failure reproduces exactly |
| `PCZT_GUARD_FUZZ_ONLY` | `both` | `generated`, `real`, or `both` |

It asserts two properties:

1. **No panics.** Any byte sequence may be rejected, but never crash. A verifier that dies has
   told the caller nothing, and a caller that reads "did not return UNSAFE" as safe is then in
   trouble.
2. **No false SAFE.** If a mutant of a known-safe PCZT is also reported `SAFE`, it must
   describe the *same* transaction: same pools, same values, same labelled addresses, same
   bound flags, same roles, same fee. Anything accepted as safe while paying somebody else is
   the bug this tool exists to prevent, and mutation is the right tool because the failure
   needs the mutant to stay structurally valid.

`committed` is compared indirectly through `bound`: `bound == true` means the committed
receiver matched the shown address via `matches_receiver`, so an equal label plus an equal
bound flag implies an equal destination. `network` is excluded on purpose — `coin_type` has no
consensus effect, and checking it is opt-in via `--expect-network`.

### What it found

On the first run, the sweep found **eight** single-byte mutations that were reported `SAFE`
while describing a completely different report: mutations around the `global` section shifted
the postcard layout so the bundles decoded as empty, leaving a valid but *empty* PCZT — which
verified `SAFE` with `fee = 0` and no payments at all.

That class is now closed by `FindingCode::EmptyTransaction` (and
`FindingCode::UnknownNetwork` for a `coin_type` naming no known chain; the same sweep produced
coin types 4200040, 32812, 256 and 2 alongside the empty bundles). Regression tests:
`an_empty_pczt_is_not_safe`, `a_coin_type_naming_no_known_network_is_not_safe`.

A useful lesson to keep: **the sweep is worth more than the random phase.** All eight hits
were single-byte, and the random mutations that followed found nothing further on the
generated seed across 150,000 attempts.

### Cost, measured

These are this machine's numbers (`--release`), so a budget can be planned rather than
guessed:

| Seed | Size | Per verification |
|---|---|---|
| generated Ironwood payment | 3.6 KB | ~6 ms |
| real `zcash-devtool` PCZT (5 actions) | 12 KB | ~18 ms |

The full single-byte sweep is `len × 3` verifications, so ~11 k for the generated seed (~65 s)
and ~36 k for the real one (~11 min). Random mutations cost the same per verification, which
is why the real seed gets a smaller random budget.

## 2. Coverage-guided, with libFuzzer

`fuzz/` — a standalone crate (`cargo-fuzz` layout), target `verify`.

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cargo +nightly fuzz build verify
cargo +nightly fuzz run verify -- -max_total_time=180 -rss_limit_mb=4096
```

The corpus in `fuzz/corpus/verify/` is seeded with the real fixtures, because random bytes
almost never survive `Pczt::parse` — without a corpus, libFuzzer spends its whole budget in
the header check. This harness also asserts the invariants the corpus cannot express directly:

* `SAFE` implies at least one pool is populated, so nothing to sign is never safe;
* `SAFE` implies every payment line is bound to an address;
* a finding's maximum severity always matches the verdict it produced (no `UNSAFE` without an
  unsafe finding, no `CANNOT VERIFY` without a cannot-verify finding).

### Windows: the ASan runtime must match the compiler

The target builds on Windows (`cargo +nightly fuzz build verify` succeeds). Running it there
needs one caveat, recorded here because it costs an hour to rediscover:

* On `x86_64-pc-windows-msvc`, `cargo-fuzz` links SanitizerCoverage, whose section symbols
  (`__stop___sancov_pcs`) come from the ASan runtime. Running the binary without that runtime
  fails at load time with `STATUS_DLL_NOT_FOUND`; putting a *mismatched* LLVM's runtime on
  `PATH` fails with `STATUS_ENTRYPOINT_NOT_FOUND`.
* `--sanitizer none` is not an escape hatch: MSVC then fails to link, with
  `LNK2001: unresolved external symbol __stop___sancov_pcs`.
* The runtime must come from the LLVM major that the nightly compiler itself uses. Check with
  `rustup run nightly rustc -vV | grep LLVM`: at the time of writing this was **23.1.4**, while
  the installed LLVM was 22.1.8 — hence no local run.

So on Linux or macOS this is a one-command affair; on Windows it needs an LLVM install matching
the toolchain. **The fuzzing evidence in `PCZT-Guard-Design.md` §10 therefore comes from the
deterministic harness above, which needs nothing but stable Rust** — and which is what found the
defects.

`fuzz/target` and `fuzz/artifacts` are git-ignored; the seed corpus is committed on purpose.

## Reproducing a finding

Both harnesses report the exact input. For the differential fuzzer, re-run with the printed
`PCZT_GUARD_FUZZ_SEED`; the PRNG is deterministic and nothing depends on wall-clock time. For
libFuzzer, the crashing input is written to `fuzz/artifacts/verify/` and can be replayed with
`cargo +nightly fuzz run verify fuzz/artifacts/verify/<file>`.
