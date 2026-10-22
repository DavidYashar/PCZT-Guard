//! Fixture CLI: build the PCZTs that PCZT Guard's tests and demo run against.
//!
//! ```text
//! cargo xtask fixtures            # write fixtures/*.pczt
//! cargo xtask describe <file>     # print what a PCZT actually commits to
//! ```

use std::{fs, path::Path};

use pczt::roles::verifier::Verifier;
use xtask::{
    address_deception, honest, inflated_fee, wallet_shaped, wallet_shaped_compacted, Payment,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("fixtures") => {
            let dir = args.get(1).map(String::as_str).unwrap_or("fixtures");
            write_fixtures(Path::new(dir))
        }
        Some("describe") => {
            let path = args.get(1).ok_or("usage: xtask describe <file.pczt>")?;
            describe(&fs::read(path)?)
        }
        _ => {
            eprintln!("usage:\n  xtask fixtures [dir]\n  xtask describe <file.pczt>");
            Ok(())
        }
    }
}

fn write_fixtures(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(dir)?;
    let honest = honest();
    let attack = address_deception();
    let drain = inflated_fee();
    let wallet_shaped = wallet_shaped();
    let wallet_compacted = wallet_shaped_compacted();

    fs::write(dir.join("ironwood-honest.pczt"), &honest.bytes)?;
    fs::write(dir.join("ironwood-address-tampered.pczt"), &attack.bytes)?;
    fs::write(dir.join("ironwood-fee-drain.pczt"), &drain.bytes)?;
    fs::write(
        dir.join("ironwood-wallet-shaped.pczt"),
        &wallet_shaped.bytes,
    )?;
    fs::write(
        dir.join("ironwood-wallet-compacted.pczt"),
        &wallet_compacted.bytes,
    )?;

    report_line("honest", &honest);
    report_line("tampered", &attack);
    report_line("fee drain", &drain);
    report_line("wallet", &wallet_shaped);
    report_line("compacted", &wallet_compacted);
    Ok(())
}

fn report_line(label: &str, payment: &Payment) {
    println!("{label:9}{} bytes", payment.bytes.len());
    match &payment.shown_address {
        Some(shown) => println!("  shown:     {}", shorten(shown)),
        None => println!("  shown:     (none)"),
    }
    println!("  committed: {}", shorten(&payment.committed_address));
    let honest = payment.shown_address.as_deref() == Some(&payment.committed_address);
    println!("  label matches the payee: {honest}");
}

fn shorten(addr: &str) -> String {
    if addr.len() <= 40 {
        addr.to_string()
    } else {
        format!("{}…{}", &addr[..24], &addr[addr.len() - 8..])
    }
}

fn status(result: Result<(), impl std::fmt::Debug>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(e) => format!("FAIL ({e:?})"),
    }
}

/// Prints what a PCZT cryptographically commits to, next to what it claims in
/// `user_address`. This is exactly the comparison PCZT Guard automates.
fn describe(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let pczt = pczt::Pczt::parse(bytes)?;
    let (version, _) = pczt
        .clone()
        .serialize_with_version()
        .map_err(|e| format!("encoding: {e:?}"))?;
    let mut lines = vec![format!("encoding: {version:?}")];

    Verifier::new(pczt)
        .with_ironwood::<String, _>(|bundle| {
            lines.push(format!(
                "bundle: {} actions · anchor deferred: {} · declared net value: {:?}",
                bundle.actions().len(),
                bundle.anchor_deferred(),
                bundle.value_sum().magnitude_sign(),
            ));
            for (index, action) in bundle.actions().iter().enumerate() {
                let spend = action.spend();
                let output = action.output();
                lines.push(format!(
                    "action {index}: spend value {:?} · output value {:?} · shown {:?}",
                    spend.value().map(|v| v.inner()),
                    output.value().map(|v| v.inner()),
                    output.user_address().as_deref().map(shorten),
                ));
                lines.push(format!(
                    "  committed recipient: {:?}",
                    output
                        .recipient()
                        .map(|r| shorten(&xtask::encode_address(r)))
                ));
                lines.push(format!(
                    "  spend: fvk {} · zip32 derivation {} · signature {}",
                    if spend.fvk().is_some() {
                        "set"
                    } else {
                        "absent"
                    },
                    if spend.zip32_derivation().is_some() {
                        "set"
                    } else {
                        "absent"
                    },
                    if spend.spend_auth_sig().is_some() {
                        "set"
                    } else {
                        "absent"
                    },
                ));
                lines.push(format!(
                    "  checks: cv_net {} · nullifier {} · rk {} · cmx {}",
                    status(action.verify_cv_net()),
                    status(spend.verify_nullifier(None)),
                    status(spend.verify_rk(None)),
                    status(output.verify_note_commitment(spend)),
                ));
            }
            Ok(())
        })
        .map_err(|e| format!("ironwood bundle: {e:?}"))?;

    for line in lines {
        println!("{line}");
    }
    Ok(())
}
