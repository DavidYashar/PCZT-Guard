#![no_main]

use libfuzzer_sys::fuzz_target;
use pczt_guard_core::{verify, FindingCode, Options, Severity, Verdict};

// Coverage-guided fuzzing of the verifier.
//
// The mutation campaign in `crates/pczt-guard-core/tests/fuzz_differential.rs` walks a known
// PCZT byte by byte; this target starts from the same corpus and lets libFuzzer's coverage
// feedback explore headers, encodings and lengths the sweep never reaches.
//
// Seeded from `fuzz/corpus/verify/`, which holds the real fixtures. Random bytes almost never
// survive `Pczt::parse`, so the corpus is what makes this worth running.
fuzz_target!(|data: &[u8]| {
    // Rejecting input is always allowed. Panicking is not: a caller that treats "did not
    // return UNSAFE" as safe learns nothing from a crash.
    let Ok(report) = verify(data, &Options::default()) else {
        return;
    };

    match report.verdict {
        Verdict::Safe => {
            // SAFE is a claim about a transaction that exists. A report with no pool cannot
            // describe one, and asserting here is what caught the empty-PCZT class.
            assert!(
                !report.pools.is_empty(),
                "SAFE with no pools: nothing to sign was reported as safe"
            );
            // Every payment line in a safe report must be bound: something the signer cannot
            // tie to an address is never safe.
            assert!(
                report.payments.iter().all(|p| p.bound),
                "SAFE with an unbound payment line"
            );
        }
        Verdict::Unsafe | Verdict::CannotVerify => {}
    }

    // A finding's severity must never outrank the verdict it produced.
    let worst = report.findings.iter().map(|f| f.severity).max();
    match report.verdict {
        Verdict::Safe => assert!(
            worst.is_none_or(|s| s == Severity::Info || s == Severity::Warn),
            "SAFE with a blocking finding"
        ),
        Verdict::Unsafe => assert_eq!(
            worst,
            Some(Severity::Unsafe),
            "UNSAFE without an unsafe finding"
        ),
        Verdict::CannotVerify => assert_eq!(
            worst,
            Some(Severity::CannotVerify),
            "CANNOT VERIFY without a cannot-verify finding"
        ),
    }

    // A cheap invariant with real weight: an empty transaction is never a signed payment.
    if report
        .findings
        .iter()
        .any(|f| f.code == FindingCode::EmptyTransaction)
    {
        assert!(report.payments.is_empty(), "an empty PCZT reported payments");
    }
});
