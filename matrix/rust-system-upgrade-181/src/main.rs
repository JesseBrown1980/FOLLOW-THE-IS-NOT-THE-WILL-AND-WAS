#![forbid(unsafe_code)]

use asolaria_system_upgrade_audit::{scan_repository, verify_baseline, write_receipt, AuditError};
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

fn usage() -> AuditError {
    AuditError::new(
        "USAGE: system-upgrade-audit scan <repo> <scope> <output> [--replace] | verify <repo> <scope> <baseline>",
    )
}

fn utf8(value: &OsString) -> Result<&str, AuditError> {
    value
        .to_str()
        .ok_or_else(|| AuditError::new("ARGUMENT_NOT_UTF8"))
}

fn run() -> Result<(), AuditError> {
    let arguments: Vec<OsString> = env::args_os().collect();
    let command = arguments.get(1).ok_or_else(usage)?;
    match utf8(command)? {
        "scan" => {
            if arguments.len() != 5 && arguments.len() != 6 {
                return Err(usage());
            }
            let replace = if let Some(flag) = arguments.get(5) {
                if utf8(flag)? != "--replace" {
                    return Err(usage());
                }
                true
            } else {
                false
            };
            let root = PathBuf::from(&arguments[2]);
            let scope = utf8(&arguments[3])?;
            let output = PathBuf::from(&arguments[4]);
            let audit = scan_repository(&root, scope)?;
            write_receipt(&output, &audit.render_hbp()?, replace)?;
            println!("{}", audit.stdout_row());
            Ok(())
        }
        "verify" => {
            if arguments.len() != 5 {
                return Err(usage());
            }
            let root = PathBuf::from(&arguments[2]);
            let scope = utf8(&arguments[3])?;
            let baseline = PathBuf::from(&arguments[4]);
            let audit = scan_repository(&root, scope)?;
            verify_baseline(&audit, &baseline)?;
            println!("{}", audit.verify_stdout_row());
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("SYSTEMUPGRADEERROR|code={}|json=0", error.code());
        std::process::exit(1);
    }
}
