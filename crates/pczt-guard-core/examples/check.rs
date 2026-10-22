//! Prints PCZT Guard's verdict for a `.pczt` file.
//!
//! ```text
//! cargo run -p pczt-guard-core --example check -- fixtures/ironwood-address-tampered.pczt
//! ```

use pczt_guard_core::{verify, Options};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: check <file.pczt>");
        return Ok(());
    };

    let bytes = std::fs::read(&path)?;
    let report = verify(&bytes, &Options::default())?;

    println!("{path}: {:?}", report.verdict);
    println!(
        "  {:?} · tx v{} · branch {:#010x} · pools: {:?}",
        report.network, report.tx_version, report.branch_id, report.pools
    );

    for payment in &report.payments {
        println!(
            "  {:?} {} zats  bound={}",
            payment.pool,
            payment
                .value
                .map_or("unknown".to_string(), |v| v.to_string()),
            payment.bound
        );
        println!("    shown:     {:?}", payment.shown);
        println!("    committed: {:?}", payment.committed);
    }

    for finding in &report.findings {
        println!(
            "  [{:?}] {:?} {:?}: {}",
            finding.severity, finding.code, finding.pool, finding.detail
        );
    }

    Ok(())
}
