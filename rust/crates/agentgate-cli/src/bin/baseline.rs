//! Baseline gate: substring matching over the raw command string.
//!
//! Reads JSON Lines on stdin, writes JSON Lines on stdout. See SPEC.md.

use std::io::{self, BufReader};

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = agentgate_core::stream::run(
        BufReader::new(stdin.lock()),
        &mut out,
        agentgate_core::baseline::analyze,
    ) {
        eprintln!("agentgate-baseline: {e}");
        std::process::exit(2);
    }
}
