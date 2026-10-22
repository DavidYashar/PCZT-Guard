//! PCZT Guard in the browser.
//!
//! The whole verifier compiled to WebAssembly. Nothing leaves the page: no network, no
//! keys, no telemetry. A signer that runs in a browser can call [`verify_pczt`] with the
//! bytes it was handed and get the same report the CLI prints.

use pczt_guard_core::{verify, Network, Options};
use wasm_bindgen::prelude::*;

/// Verifies a serialized PCZT and returns the report as JSON.
///
/// * `pczt` — the raw bytes of a `.pczt` file.
/// * `expected_network` — `"main"` or `"test"` to reject a PCZT built for another network.
/// * `strict` — treat warnings (privacy leaks, excessive fees) as failures.
/// * `allow_unlabeled_change` — do not treat an output with no `user_address` as
///   unverifiable.
///
/// Throws if the bytes are not a PCZT. Every other problem is in the returned report.
#[wasm_bindgen]
pub fn verify_pczt(
    pczt: &[u8],
    expected_network: Option<String>,
    strict: bool,
    allow_unlabeled_change: bool,
) -> Result<String, JsError> {
    let options = Options {
        expected_network: expected_network.as_deref().and_then(parse_network),
        allow_unlabeled_change,
        strict,
        // Viewing keys stay out of the browser build: that is what makes the page safe to
        // run on a machine you do not trust. `ufvks` and `at_height` keep their defaults.
        ..Options::default()
    };

    let report = verify(pczt, &options).map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&report).map_err(|e| JsError::new(&e.to_string()))
}

fn parse_network(name: &str) -> Option<Network> {
    match name {
        "main" | "mainnet" => Some(Network::Main),
        "test" | "testnet" => Some(Network::Test),
        _ => None,
    }
}

/// The version of the verifier compiled into this page.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
