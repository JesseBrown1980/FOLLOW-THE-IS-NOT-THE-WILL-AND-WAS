#![forbid(unsafe_code)]

use rust_qprism_181::outward::run_outward;
use rust_qprism_181::QprismError;
use std::env;
use std::path::PathBuf;

fn main() {
    if let Err(error) = entry() {
        eprintln!("OUTWARD181|PASS=0|reason={}|json=0", error.code());
        std::process::exit(1);
    }
}

fn entry() -> Result<(), QprismError> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 4 || arguments[3] != "--replace" {
        return Err(QprismError::new("USAGE_INPUT_OUTPUT_DIR_REPLACE"));
    }
    let result = run_outward(
        &PathBuf::from(&arguments[1]),
        &PathBuf::from(&arguments[2]),
        true,
    )?;
    println!(
        "OUTWARD181|PASS=1|repositories={}|waves={}|hbp_sha256={}|hbi_sha256={}|svg_sha256={}|gguf_sha256={}|json=0",
        result.repositories,
        result.waves,
        result.hbp_sha256,
        result.hbi_sha256,
        result.svg_sha256,
        result.gguf_sha256
    );
    Ok(())
}
