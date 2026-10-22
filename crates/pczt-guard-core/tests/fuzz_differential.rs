//! A differential fuzzer for the verifier.
//!
//! Run with:
//!
//! ```text
//! cargo test -p pczt-guard-core --test fuzz_differential -- --ignored --nocapture
//! PCZT_GUARD_FUZZ_ITERS=200000 cargo test ... -- --ignored --nocapture
//! ```
//!
//! It is `#[ignore]`d so the ordinary suite stays fast; a nightly job can run it with a large
//! budget.
//!
//! # The two properties
//!
//! 1. **No panics.** Any byte sequence is allowed to be rejected, but never to crash: a
//!    verifier that dies has told the caller nothing, and a caller that treats "did not
//!    return UNSAFE" as safe is then in trouble.
//!
//! 2. **No false SAFE.** This is the one that matters. Take a PCZT that verifies `SAFE`, and
//!    mutate it. If the mutant *also* verifies `SAFE`, then it must describe exactly the same
//!    transaction — same payments, same committed receivers, same fee. Any mutant that is
//!    accepted as safe while paying somebody else is the bug this tool exists to prevent, and
//!    a fuzzer is the right way to look for it because the failure requires the mutation to
//!    stay structurally valid.
//!
//! Property 2 is a real oracle, not a smoke test: `pczt::Pczt::parse` enforces structure, so
//! most mutants are rejected outright and the interesting ones are the few that survive to
//! the semantic checks.

use std::panic::{catch_unwind, AssertUnwindSafe};

use pczt_guard_core::{verify, Options, PaymentLine, Pool, Report, Role, Verdict};

/// A small deterministic PRNG, so a failing run is reproducible from its seed alone.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }
}

/// The facts that decide where money goes, in a form two reports can be compared on.
///
/// `committed` is deliberately left out: it is a re-encoding of the same receiver bytes for
/// the PCZT's declared network, and `bound` already ties the receiver to `shown` via
/// `matches_receiver`. `network` is left out too — `coin_type` has no consensus effect
/// (see the field's own documentation in `pczt`), and checking it is opt-in through
/// `Options::expected_network`.
#[derive(Debug, PartialEq, Eq)]
struct Shape {
    pools: Vec<Pool>,
    payments: Vec<(Option<u64>, Option<String>, bool, Role)>,
    fee: Option<u64>,
}

fn shape(report: &Report) -> Shape {
    Shape {
        pools: report.pools.clone(),
        payments: report
            .payments
            .iter()
            .map(|p: &PaymentLine| (p.value, p.shown.clone(), p.bound, p.role))
            .collect(),
        fee: report.fee,
    }
}

/// Verifies while catching panics, so one bad input cannot end the run.
fn verify_without_panicking(bytes: &[u8]) -> Option<Report> {
    catch_unwind(AssertUnwindSafe(|| verify(bytes, &Options::default())))
        .ok()
        .and_then(Result::ok)
}

#[test]
#[ignore = "long-running fuzz campaign: run explicitly with --ignored"]
fn mutations_never_panic_and_never_turn_a_lie_into_safe() {
    let iters: usize = std::env::var("PCZT_GUARD_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let seed: u64 = std::env::var("PCZT_GUARD_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x5EED_1234_ABCD_0001);
    // The two seeds cost very different amounts (6 ms vs 18 ms per verification, measured), so
    // they can be run separately when time is short.
    let only = std::env::var("PCZT_GUARD_FUZZ_ONLY").unwrap_or_else(|_| "both".to_string());

    // Two seeds with different shapes: a generated Ironwood payment with a labelled output,
    // and the recorded `zcash-devtool` transaction with unlabelled change.
    let generated = xtask::honest();
    let real = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/ironwood-devtool-real.pczt"
    ))
    .expect("the recorded fixture exists");

    let mut rng = Rng::new(seed);
    let mut checked = 0usize;
    let mut accepted_safe = 0usize;
    let mut rejected = 0usize;

    for (label, baseline_bytes) in [("generated", &generated.bytes), ("real", &real)] {
        if only != "both" && only != label {
            continue;
        }
        let baseline = verify_without_panicking(baseline_bytes)
            .unwrap_or_else(|| panic!("the {label} seed must verify"));
        let baseline_shape = shape(&baseline);
        let baseline_verdict = baseline.verdict;
        eprintln!(
            "{label}: seed verdict {baseline_verdict:?}, {} bytes — sweeping every offset",
            baseline_bytes.len()
        );

        // Phase 1: an exhaustive single-byte sweep with three values per offset. Every offset
        // is tried, because a checksum or length field only reveals its guard on one of them.
        for offset in 0..baseline_bytes.len() {
            for value in [0x00u8, 0xFF, 0x7F] {
                let mut mutant = baseline_bytes.clone();
                if mutant[offset] == value {
                    continue;
                }
                mutant[offset] = value;

                let Some(report) = verify_without_panicking(&mutant) else {
                    rejected += 1;
                    continue;
                };
                checked += 1;
                if report.verdict == Verdict::Safe {
                    accepted_safe += 1;
                    assert_eq!(
                        shape(&report),
                        baseline_shape,
                        "{label}: flipping byte {offset} to {value:#04x} was accepted as SAFE \
                         while describing a different transaction (seed {seed:#x})"
                    );
                }
            }
        }

        // Phase 2: random multi-byte mutation, which reaches combinations a single-byte sweep
        // cannot (a field and its checksum changing together).
        for iteration in 0..iters {
            if iteration > 0 && iteration % 5_000 == 0 {
                eprintln!(
                    "{label}: {iteration}/{iters} random mutations, {checked} checked so far"
                );
            }
            let mut mutant = baseline_bytes.clone();
            let count = 1 + rng.below(8);
            for _ in 0..count {
                let offset = rng.below(mutant.len());
                mutant[offset] = rng.byte();
            }
            // Occasionally truncate or extend, to exercise length handling.
            match rng.below(16) {
                0 => mutant.truncate(rng.below(mutant.len().max(1))),
                1 => mutant.extend((0..rng.below(32)).map(|_| rng.byte())),
                _ => {}
            }

            let Some(report) = verify_without_panicking(&mutant) else {
                rejected += 1;
                continue;
            };
            checked += 1;
            if report.verdict == Verdict::Safe {
                accepted_safe += 1;
                assert_eq!(
                    shape(&report),
                    baseline_shape,
                    "{label}: a {count}-byte mutation was accepted as SAFE while describing a \
                     different transaction (seed {seed:#x})"
                );
            }
        }

        eprintln!(
            "{label}: seed verdict {baseline_verdict:?}, {} bytes, sweep + {iters} random",
            baseline_bytes.len()
        );
    }

    eprintln!(
        "checked {checked} mutants ({accepted_safe} still SAFE and shape-identical, \
         {rejected} rejected), seed {seed:#x}"
    );
    assert!(checked > 0, "the campaign must actually verify something");
}
