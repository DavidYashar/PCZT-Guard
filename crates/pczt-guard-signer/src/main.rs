//! A reference signer for Orchard and Ironwood spends in a PCZT.
//!
//! `zcash-devtool 0.1.0` cannot sign Ironwood spends: `pczt sign` calls only
//! `with_orchard`/`sign_orchard`, so on any post-NU6.3 transaction it exits 0, writes a
//! byte-identical file, and `pczt send` then fails with `MissingSpendAuthSig`.
//!
//! This tool does the missing half with the same `pczt` Signer role the rest of the
//! ecosystem uses, so the result can be proved and broadcast.
//!
//! ```text
//! pczt-guard-signer --pczt payment.pczt --mnemonic-file phrase.txt --network test --output signed.pczt
//! ```
//!
//! The mnemonic is read from a file rather than an argument, so it never lands in shell
//! history or a process listing.
//!
//! # It refuses to sign what it cannot stand behind
//!
//! Before touching a key, the signer runs PCZT Guard over the same bytes, using the
//! viewing key it is about to sign with. That is stronger than either half alone: the
//! key proves which outputs are this wallet's own change, so an output that is neither
//! labelled nor ours is refused rather than warned about. An `UNSAFE` verdict is final;
//! `CANNOT VERIFY` needs `--allow-unverified`, so that signing something unexamined has
//! to be asked for out loud.

use std::{convert::Infallible, fs, process::ExitCode};

use orchard::keys::{FullViewingKey, SpendAuthorizingKey};
use pczt::{
    roles::{signer::Signer, verifier::Verifier},
    Pczt,
};
use pczt_guard_core::{Options as GuardOptions, Verdict};
use rand_core::UnwrapErr;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::Network;
use zip32::AccountId;

fn main() -> ExitCode {
    match run() {
        Ok(Some(signed)) => {
            println!("pczt-guard-signer: signed {signed} spend(s)");
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pczt-guard-signer: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `Some(n)` when `n` spends were signed, `None` when the run printed what it was asked
/// for and stopped (`--print-ufvk`, `--dry-run`).
fn run() -> Result<Option<usize>, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let pczt_path = value_of(&args, "--pczt");
    let mnemonic_path = value_of(&args, "--mnemonic-file")
        .ok_or("--mnemonic-file <file> is required (the phrase on one line)")?;
    let network_name = value_of(&args, "--network").unwrap_or_else(|| "test".to_string());

    let network = match network_name.as_str() {
        "main" | "mainnet" => Network::MainNetwork,
        "test" | "testnet" => Network::TestNetwork,
        other => return Err(format!("unknown network {other:?}; use main or test").into()),
    };

    let phrase = read_phrase(&mnemonic_path)?;
    let mnemonic = bip39::Mnemonic::parse(phrase.trim())
        .map_err(|e| format!("the mnemonic file is not a valid BIP-39 phrase: {e}"))?;

    // ZIP 32 takes the BIP-39 seed; zcash-devtool wallets use account 0.
    let seed = mnemonic.to_seed("");
    let account = AccountId::try_from(0u32).map_err(|e| format!("account 0: {e:?}"))?;
    let usk = UnifiedSpendingKey::from_seed(&network, &seed, account)
        .map_err(|e| format!("deriving the spending key: {e:?}"))?;

    let sk = usk.orchard();
    let ask = SpendAuthorizingKey::from(sk);
    let fvk = FullViewingKey::from(sk);

    // The viewing key is what PCZT Guard needs to prove which outputs are this wallet's
    // change. Printing it lets the same wallet be checked offline without the phrase.
    if args.iter().any(|a| a == "--print-ufvk") {
        let ufvk = zcash_keys::keys::UnifiedFullViewingKey::from_orchard_fvk(fvk)
            .map_err(|e| format!("building the unified viewing key: {e:?}"))?;
        println!(
            "{}",
            ufvk.encode(&network)
                .map_err(|e| format!("encoding the viewing key: {e:?}"))?
        );
        return Ok(None);
    }

    let pczt_path = pczt_path.ok_or("--pczt <file> is required")?;
    let output = value_of(&args, "--output").unwrap_or_else(|| pczt_path.clone());

    let bytes = fs::read(&pczt_path)?;
    let pczt = Pczt::parse(&bytes).map_err(|e| format!("{pczt_path} is not a PCZT: {e:?}"))?;

    refuse_unless_safe(
        &bytes,
        network,
        &fvk,
        args.iter().any(|a| a == "--allow-unverified"),
    )?;

    // Find the spends that need a signature and belong to this key. Every Orchard-family
    // spend in a PCZT carries its FVK, so ownership is checkable before anything is signed.
    let mut ironwood = Vec::new();
    Verifier::new(pczt.clone())
        .with_ironwood::<Infallible, _>(|bundle| {
            ironwood = unsigned_ours(bundle, &fvk);
            Ok(())
        })
        .map_err(|e| format!("reading the Ironwood bundle: {e:?}"))?;
    let mut orchard = Vec::new();
    Verifier::new(pczt.clone())
        .with_orchard::<Infallible, _>(|bundle| {
            orchard = unsigned_ours(bundle, &fvk);
            Ok(())
        })
        .map_err(|e| format!("reading the Orchard bundle: {e:?}"))?;

    let total = ironwood.len() + orchard.len();
    if total == 0 {
        return Err(
            "no unsigned spend belongs to this mnemonic: wrong phrase, or already signed".into(),
        );
    }

    if args.iter().any(|a| a == "--dry-run") {
        println!("pczt-guard-signer: --dry-run, would sign {total} spend(s)");
        return Ok(None);
    }

    let mut signer = Signer::new(pczt).map_err(|e| format!("opening the signer: {e:?}"))?;
    for index in &ironwood {
        signer
            .sign_ironwood(UnwrapErr(rand::rngs::SysRng), *index, &ask)
            .map_err(|e| format!("signing Ironwood spend {index}: {e:?}"))?;
    }
    for index in &orchard {
        signer
            .sign_orchard(UnwrapErr(rand::rngs::SysRng), *index, &ask)
            .map_err(|e| format!("signing Orchard spend {index}: {e:?}"))?;
    }

    let signed = signer.finish();
    fs::write(
        &output,
        signed.serialize().map_err(|e| format!("encoding: {e:?}"))?,
    )?;
    Ok(Some(total))
}

/// Runs PCZT Guard with the key about to be used, and refuses to go on unless it is safe.
///
/// `UNSAFE` is always fatal: something in the PCZT is provably false, and a signature on it
/// cannot be taken back. `CANNOT VERIFY` is fatal unless the caller asked for it, because a
/// check that could not run is not a check that passed.
fn refuse_unless_safe(
    bytes: &[u8],
    network: Network,
    fvk: &FullViewingKey,
    allow_unverified: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let options = GuardOptions {
        expected_network: Some(match network {
            Network::MainNetwork => pczt_guard_core::Network::Main,
            Network::TestNetwork => pczt_guard_core::Network::Test,
        }),
        // The key that will sign also proves which outputs are its own change, which is the
        // difference between "somebody's unlabelled output" and "my change".
        ufvks: vec![fvk.clone()],
        // `--allow-unverified` is the caller saying "sign it anyway"; it downgrades the two
        // ownership classes that would otherwise block, and nothing else.
        allow_unlabeled_change: allow_unverified,
        ..GuardOptions::default()
    };

    let report =
        pczt_guard_core::verify(bytes, &options).map_err(|e| format!("not signable: {e}"))?;

    if report.verdict == Verdict::Safe {
        let own = report
            .payments
            .iter()
            .filter(|p| p.role != pczt_guard_core::Role::External)
            .count();
        println!(
            "pczt-guard-signer: PCZT Guard says SAFE ({} external payment(s), {own} output(s) \
             proven to be this wallet's own)",
            report.payments.len() - own
        );
        // A fee the user did not expect is money spent, so the number is printed rather than
        // left in a report nobody reads. `HighFee` is a warning, and a warning that never
        // reaches the person signing is not a warning.
        if let Some(fee) = report.fee {
            println!(
                "pczt-guard-signer: fee {}.{:08} ZEC",
                fee / 100_000_000,
                fee % 100_000_000
            );
        }
        for finding in report
            .findings
            .iter()
            .filter(|f| f.severity == pczt_guard_core::Severity::Warn)
        {
            eprintln!("pczt-guard-signer: warning: {}", finding.detail);
        }
        return Ok(());
    }

    let mut message = format!(
        "PCZT Guard says {:?}, so this PCZT is not being signed",
        report.verdict
    );
    for finding in report
        .findings
        .iter()
        .filter(|f| f.severity >= pczt_guard_core::Severity::CannotVerify)
    {
        message.push_str(&format!("\n  {:?}: {}", finding.code, finding.detail));
    }

    match report.verdict {
        Verdict::Unsafe => Err(message.into()),
        _ if allow_unverified => {
            eprintln!("{message}\n  (continuing because --allow-unverified was given)");
            Ok(())
        }
        _ => {
            message.push_str(
                "\n  supply the wallet's viewing key with --ufvk, or pass --allow-unverified \
                 to sign anyway",
            );
            Err(message.into())
        }
    }
}

/// Indices of spends in this bundle that have no signature yet and carry our FVK.
fn unsigned_ours(bundle: &orchard::pczt::Bundle, fvk: &FullViewingKey) -> Vec<usize> {
    let ours = fvk.to_bytes();
    bundle
        .actions()
        .iter()
        .enumerate()
        .filter(|(_, action)| {
            let spend = action.spend();
            let is_ours = match spend.fvk() {
                Some(f) => f.to_bytes() == ours,
                None => false,
            };
            spend.spend_auth_sig().is_none() && is_ours
        })
        .map(|(index, _)| index)
        .collect()
}

fn value_of(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Reads a mnemonic file written by any of the usual Windows incantations.
///
/// `>` redirection in Windows PowerShell writes UTF-16LE, `Out-File -Encoding utf8` adds a
/// BOM, and `Set-Content` writes the ANSI code page. All of them are common, none of them is
/// worth making the user debug, so decode them all here.
fn read_phrase(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    pczt_guard_core::decode_text(&bytes).ok_or_else(|| {
        format!("{path} is not decodable as UTF-8 or UTF-16; write the phrase as plain ASCII")
            .into()
    })
}

#[cfg(test)]
mod gate {
    use super::*;

    fn owner_key() -> FullViewingKey {
        xtask::owner().1
    }

    #[test]
    fn refuses_to_sign_a_tampered_pczt() {
        let payment = xtask::address_deception();
        let error = refuse_unless_safe(&payment.bytes, Network::TestNetwork, &owner_key(), true)
            .expect_err("the label lies about who is paid");
        let message = error.to_string();
        assert!(message.contains("AddressMismatch"), "{message}");
        assert!(message.contains("not being signed"), "{message}");
    }

    #[test]
    fn an_unverified_pczt_has_to_be_asked_for() {
        let payment = xtask::redacted_recipient();
        assert!(
            refuse_unless_safe(&payment.bytes, Network::TestNetwork, &owner_key(), false).is_err(),
            "a check that could not run is not a pass"
        );
        assert!(
            refuse_unless_safe(&payment.bytes, Network::TestNetwork, &owner_key(), true).is_ok(),
            "--allow-unverified is the way to say yes anyway"
        );
    }

    #[test]
    fn proves_change_with_the_key_it_is_about_to_sign_with() {
        let payment = xtask::payment_with_change();
        assert!(
            refuse_unless_safe(&payment.bytes, Network::TestNetwork, &owner_key(), false).is_ok()
        );
    }

    #[test]
    fn an_unverified_override_cannot_rescue_a_proven_alien_output() {
        // The flag exists to accept what could not be checked. A viewing key checked this
        // output and proved it pays somebody else, so `--allow-unverified` must not turn
        // that into a signature.
        let payment = xtask::payment_with_change();
        assert!(
            refuse_unless_safe(&payment.bytes, Network::TestNetwork, &alice_key(), true).is_err(),
            "a proven alien output is not overridable"
        );
    }

    fn alice_key() -> FullViewingKey {
        xtask::alice_fvk()
    }
}
