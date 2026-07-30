#![forbid(unsafe_code)]

use rust_qprism_181::{run, QprismError};
use std::env;
use std::path::PathBuf;

fn main() {
    if let Err(error) = entry() {
        eprintln!("QPRISM181|PASS=0|reason={}|json=0", error.code());
        std::process::exit(1);
    }
}

fn entry() -> Result<(), QprismError> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 5 || arguments[4] != "--replace" {
        return Err(QprismError::new("USAGE_INPUT_RECEIPT_SVG_REPLACE"));
    }
    let result = run(
        &PathBuf::from(&arguments[1]),
        &PathBuf::from(&arguments[2]),
        &PathBuf::from(&arguments[3]),
        true,
    )?;
    println!(
        "QPRISM181|PASS=1|records={}|leaves={}|receipt_sha256={}|svg_sha256={}|json=0",
        result.records, result.leaves, result.receipt_sha256, result.svg_sha256
    );
    Ok(())
}
