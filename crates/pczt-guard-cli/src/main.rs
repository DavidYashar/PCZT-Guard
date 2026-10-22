//! `pczt-guard` — check the cheque before you sign it.
//!
//! Exit codes are the point of this binary. A signing script runs
//!
//! ```text
//! pczt-guard check payment.pczt || exit 1
//! ```
//!
//! and a non-zero code stops the signature.
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | `SAFE` — every claim was re-derived and matched |
//! | 1 | `UNSAFE` — the PCZT asserts something false, or strict mode found a leak |
//! | 2 | `CANNOT VERIFY` — something needed for a check is missing |
//! | 3 | the input is not a PCZT, or the command line is wrong |

use std::{
    io::{self, Read},
    process::ExitCode,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use pczt_guard_core::{
    verify, Finding, Network, Options, PaymentLine, Report, Role, Severity, Verdict,
};

const EXIT_SAFE: u8 = 0;
const EXIT_UNSAFE: u8 = 1;
const EXIT_UNVERIFIED: u8 = 2;
const EXIT_ERROR: u8 = 3;

#[derive(Parser)]
#[command(
    name = "pczt-guard",
    version,
    about = "Check a Zcash PCZT before signing it",
    long_about = "PCZT Guard re-derives every claim a partially created Zcash transaction makes \
                  about itself, including the one claim no signer checks: that the address shown \
                  to the user is the address the money goes to.\n\nIt never needs a spending key \
                  and never touches the network."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a PCZT and report whether it is safe to sign
    Check(Check),
    /// List the privacy lints PCZT Guard applies
    Lints,
}

#[derive(Args)]
struct Check {
    /// The PCZT to check, or `-` to read it from stdin
    path: String,

    /// The network this signer expects, rejecting a PCZT built for another one
    #[arg(long, value_enum)]
    expect_network: Option<NetworkArg>,

    /// Do not treat an output with no user_address as unverifiable
    #[arg(long)]
    allow_unlabeled_change: bool,

    /// The signer's own unified full viewing key, to prove unlabelled change is yours
    ///
    /// Repeatable, for wallets with more than one account. A viewing key cannot spend.
    #[arg(long = "ufvk", value_name = "UFVK")]
    ufvk: Vec<String>,

    /// A file of unified full viewing keys, one per line (`#` starts a comment)
    #[arg(long = "ufvk-file", value_name = "PATH")]
    ufvk_file: Option<String>,

    /// The chain height to compare the PCZT's expiry height against
    #[arg(long = "at-height", value_name = "HEIGHT")]
    at_height: Option<u32>,

    /// Treat warnings (privacy leaks, excessive fees) as failures
    #[arg(long)]
    strict: bool,

    /// Print the report as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum NetworkArg {
    Main,
    Test,
}

impl From<NetworkArg> for Network {
    fn from(value: NetworkArg) -> Self {
        match value {
            NetworkArg::Main => Network::Main,
            NetworkArg::Test => Network::Test,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Check(check) => check.run(),
        Command::Lints => {
            print_lints();
            ExitCode::SUCCESS
        }
    }
}

/// The rules PCZT Guard applies, in order. IDs are stable so they can be cited.
const LINTS: &[(&str, &str, &str)] = &[
    (
        "PL01",
        "warn",
        "the transaction spends transparent inputs, publishing its link to their history",
    ),
    (
        "PL02",
        "warn",
        "a transparent output belongs to this wallet, so its change is public",
    ),
    (
        "PL03",
        "info",
        "value crosses the Orchard/Ironwood turnstile, so the crossing amount is visible",
    ),
    (
        "PL04",
        "info",
        "an amount visible to everyone is not round, and a distinctive amount is a fingerprint",
    ),
    (
        "PL06",
        "info",
        "the transaction touches more than one shielded pool, linking them",
    ),
    (
        "PL07",
        "warn",
        "the fee is far above what ZIP 317 charges for a transaction of this shape",
    ),
];

fn print_lints() {
    println!("PCZT Guard privacy lints");
    println!();
    for (id, severity, description) in LINTS {
        println!("  {id}  {severity:<5} {description}");
    }
    println!();
    println!("  --strict turns every warning into a failure, because a leak cannot be undone.");
    println!("  PL05 (a memo a transparent recipient discards) needs a viewing key, so it is");
    println!("  not applied: a PCZT carries no record of the sender's intent.");
}

impl Check {
    fn run(self) -> ExitCode {
        let bytes = match read_input(&self.path) {
            Ok(bytes) => bytes,
            Err(e) => return fail(&format!("cannot read {}: {e}", self.path)),
        };

        let ufvks = match owned_ufvks(&self) {
            Ok(ufvks) => ufvks,
            Err(e) => return fail(&e),
        };

        let options = Options {
            expected_network: self.expect_network.map(Network::from),
            allow_unlabeled_change: self.allow_unlabeled_change,
            strict: self.strict,
            ufvks,
            at_height: self.at_height,
        };

        let report = match verify(&bytes, &options) {
            Ok(report) => report,
            Err(e) => return fail(&e.to_string()),
        };

        if self.json {
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{json}"),
                Err(e) => return fail(&format!("cannot encode the report: {e}")),
            }
        } else {
            print_human(&self.path, &report, self.strict);
        }

        ExitCode::from(match report.verdict {
            Verdict::Safe => EXIT_SAFE,
            Verdict::Unsafe => EXIT_UNSAFE,
            Verdict::CannotVerify => EXIT_UNVERIFIED,
        })
    }
}

fn read_input(path: &str) -> io::Result<Vec<u8>> {
    if path == "-" {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        Ok(bytes)
    } else {
        std::fs::read(path)
    }
}

/// Every viewing key the caller named, decoded into the Orchard component Guard uses.
///
/// A unified full viewing key is validated against the network in its own prefix, so each
/// one is offered to every network rather than requiring the caller to say which.
fn owned_ufvks(check: &Check) -> Result<Vec<orchard::keys::FullViewingKey>, String> {
    use zcash_protocol::consensus::Network;

    let mut encodings: Vec<String> = check.ufvk.clone();
    if !encodings.is_empty() {
        // A viewing key on the command line is readable by other local users through
        // `ps`/`/proc/<pid>/cmdline` and is kept in shell history and CI logs. It cannot
        // spend, but it reveals every note the wallet receives.
        eprintln!(
            "pczt-guard: note: --ufvk puts the key in this process's command line, where other \
             users and shell history can read it; prefer --ufvk-file"
        );
    }
    if let Some(path) = &check.ufvk_file {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("cannot read the viewing key file {path}: {e}"))?;
        // PowerShell's `>` writes UTF-16, so the file is decoded the same tolerant way the
        // signer reads a mnemonic file.
        let text = pczt_guard_core::decode_text(&bytes).ok_or_else(|| {
            format!("the viewing key file {path} is not decodable as UTF-8 or UTF-16")
        })?;
        encodings.extend(
            text.lines()
                .map(|line| line.split('#').next().unwrap_or("").trim())
                .filter(|line| !line.is_empty())
                .map(str::to_owned),
        );
    }

    let mut keys = Vec::new();
    for encoding in encodings {
        let mut decoded = None;
        for network in [Network::MainNetwork, Network::TestNetwork] {
            if let Ok(ufvk) = zcash_keys::keys::UnifiedFullViewingKey::decode(&network, &encoding) {
                decoded = Some(ufvk);
                break;
            }
        }
        let Some(ufvk) = decoded else {
            // The value is never echoed, even in part: a phrase pasted into the wrong flag
            // would otherwise leak its first and last characters into a log.
            return Err(
                "a viewing key does not decode as a unified full viewing key for any network \
                 (check it is a `uview…` key, not a mnemonic or a transparent address)"
                    .to_string(),
            );
        };
        match ufvk.orchard() {
            Some(orchard) => keys.push(orchard.clone()),
            None => {
                return Err(
                    "a viewing key carries no Orchard receiver, so it cannot decrypt Ironwood \
                     or Orchard outputs"
                        .to_string(),
                )
            }
        }
    }
    Ok(keys)
}

fn fail(message: &str) -> ExitCode {
    eprintln!("pczt-guard: {message}");
    ExitCode::from(EXIT_ERROR)
}

fn print_human(path: &str, report: &Report, strict: bool) {
    println!("{}", verdict_line(report, strict));
    println!(
        "  {path} · {} · tx v{} · {}",
        network_name(report.network),
        report.tx_version,
        if report.pools.is_empty() {
            "no inputs or outputs".to_string()
        } else {
            report
                .pools
                .iter()
                .map(|p| format!("{p:?}").to_lowercase())
                .collect::<Vec<_>>()
                .join(" + ")
        }
    );

    if !report.payments.is_empty() {
        println!();
        for payment in &report.payments {
            println!("  {}", payment_line(payment));
        }
        if let Some(fee) = report.fee {
            println!("  {:<9}{}", "fee", zec(fee));
        }
    }

    if !report.findings.is_empty() {
        println!();
        for finding in &report.findings {
            println!("{}", finding_line(finding));
        }
    }
}

fn verdict_line(report: &Report, strict: bool) -> String {
    match report.verdict {
        Verdict::Safe => "SAFE".to_string(),
        Verdict::Unsafe if strict => "UNSAFE (strict mode: warnings are failures here)".to_string(),
        Verdict::Unsafe => "UNSAFE".to_string(),
        Verdict::CannotVerify => "CANNOT VERIFY".to_string(),
    }
}

fn payment_line(payment: &PaymentLine) -> String {
    let pool = format!("{:?}", payment.pool).to_lowercase();
    let value = payment.value.map_or("unknown value".to_string(), zec);
    match payment.role {
        Role::Change => {
            let address = payment.committed.as_deref().unwrap_or("(this wallet)");
            format!("{pool:<9}{value} → {}  [change, proven]", shorten(address))
        }
        Role::SelfTransfer => {
            let address = payment.shown.as_deref().unwrap_or("(this wallet)");
            format!("{pool:<9}{value} → {}  [yours, proven]", shorten(address))
        }
        Role::External => {
            let address = payment.shown.as_deref().unwrap_or("(no address)");
            let status = if payment.bound {
                "verified"
            } else {
                "NOT verified"
            };
            format!("{pool:<9}{value} → {}  [{status}]", shorten(address))
        }
    }
}

fn finding_line(finding: &Finding) -> String {
    let marker = match finding.severity {
        Severity::Unsafe => "unsafe",
        Severity::CannotVerify => "unverified",
        Severity::Warn => "warn",
        Severity::Info => "info",
    };
    let pool = finding
        .pool
        .map(|p| format!(" {:?}", p).to_lowercase())
        .unwrap_or_default();
    let lint = finding.lint.map(|id| format!("{id} ")).unwrap_or_default();
    format!(
        "  {marker:<10} {lint}{:?}{pool}: {}",
        finding.code, finding.detail
    )
}

fn network_name(network: Network) -> &'static str {
    match network {
        Network::Main => "mainnet",
        Network::Test => "testnet",
        Network::Other(_) => "unknown network",
    }
}

/// Zatoshis to ZEC, with the eight decimals people expect to see on a receipt.
fn zec(zats: u64) -> String {
    format!("{}.{:08} ZEC", zats / 100_000_000, zats % 100_000_000)
}

/// Renders an untrusted string for a terminal.
///
/// `user_address` comes from a file the signer did not write, and the terminal is where the
/// verdict is read. A raw `ESC[2K` / `ESC[3A` pair erases the lines above and repaints the
/// verdict, and a bidirectional override reorders the glyphs so an address reads differently
/// from its bytes. Both are escaped rather than printed. This is defence in depth:
/// [`pczt_guard_core`] also reports such a label as `UNSAFE`.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if pczt_guard_core::is_display_hazard(c) {
                format!("\\u{{{:x}}}", u32::from(c))
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Shortens a long address for display, on character boundaries so a multi-byte character
/// can never split and panic.
fn shorten(address: &str) -> String {
    let address = printable(address);
    if address.chars().count() <= 40 {
        return address;
    }
    let head: String = address.chars().take(20).collect();
    let tail: String = address
        .chars()
        .rev()
        .take(12)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail}")
}
