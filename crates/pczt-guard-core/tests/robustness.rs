//! Malformed input must never crash the verifier.
//!
//! A signer feeds PCZT Guard bytes from an untrusted party. If those bytes can panic the
//! verifier, an attacker has a denial-of-service on the check itself — which is enough to
//! make a user fall back to signing without it.
//!
//! These are property tests rather than a `cargo-fuzz` target so they run on stable in the
//! normal test suite; `cargo fuzz` remains available for longer campaigns.

use pczt_guard_core::{verify, Options};

/// xorshift64*, so the corpus is deterministic and needs no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

/// Runs the verifier and ignores the answer: the assertion is that it returns at all.
fn survives(bytes: &[u8]) {
    let _ = verify(bytes, &Options::default());
}

#[test]
fn random_bytes_do_not_panic() {
    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    for length in [0usize, 1, 2, 3, 8, 16, 64, 255, 1024, 4096] {
        for _ in 0..40 {
            let bytes: Vec<u8> = (0..length).map(|_| rng.next() as u8).collect();
            survives(&bytes);
        }
    }
}

#[test]
fn every_truncation_of_a_valid_pczt_does_not_panic() {
    let bytes = xtask::honest().bytes;
    // Every length up to 256, then a sample: the point is coverage of the length-prefixed
    // parse path, not of every offset. A long campaign belongs in cargo-fuzz.
    for length in 0..bytes.len().min(256) {
        survives(&bytes[..length]);
    }
    for length in (256..bytes.len()).step_by(64) {
        survives(&bytes[..length]);
    }
}

#[test]
fn mutations_of_a_valid_pczt_do_not_panic() {
    let original = xtask::honest().bytes;
    let mut rng = Rng(0xC0FF_EE00_1234_5678);

    for _ in 0..150 {
        let mut bytes = original.clone();
        // Between one and four corrupted bytes, anywhere in the PCZT.
        for _ in 0..=rng.below(4) {
            let index = rng.below(bytes.len());
            bytes[index] ^= (rng.next() as u8) | 1;
        }
        survives(&bytes);
    }
}

#[test]
fn trailing_garbage_does_not_panic() {
    let mut bytes = xtask::honest().bytes;
    bytes.extend_from_slice(&[0xFF; 64]);
    survives(&bytes);
}
