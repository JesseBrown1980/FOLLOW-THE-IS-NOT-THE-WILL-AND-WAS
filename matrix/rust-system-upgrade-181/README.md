# Rust 1.81 system-upgrade audit

This dependency-free Rust cell turns the full-system migration target into a
ratcheting HBP gate. It audits the actual Git worktree bytes and keeps these
populations separate:

- sealed .hbp and .hbi artifacts and their exact LF SHA-256 sidecars;
- .sh shell programs versus the SH member of {HBI,HBP,SHA,SH,HASH};
- Rust and non-Rust source files that reference HBP/HBI surfaces;
- exact Rust 1.81.0, package rust-version, checked release overflow,
  unsafe-code prohibition, clippy, float-arithmetic linting, and code-level
  floating-point candidates;
- current migration debt versus the final all-zero target.

Historical receipts stay byte-sealed. Their active producers and verifiers move
to the new gate; a historical artifact is not rewritten merely to change the
language that originally emitted it.

Continuously served pages are measured while they remain running. Page tests
sample named process, listener, rendered-state, feed-freshness, counter, hash,
and error invariants, then close the page explicitly during teardown. A timeout
is a watchdog boundary, not page completion. Historical bounded timed witnesses
and deterministic fake-clock receipts remain a separate evidence stratum.

The audit output publishes domain-separated source identifiers and aggregate
counts. It keeps raw paths and private repository identities outside the public
receipt.

    cargo +1.81.0 run --manifest-path matrix/rust-system-upgrade-181/Cargo.toml -- \
      scan . FOLLOW-THE-IS-PUBLIC-HARNESS matrix/SYSTEM-UPGRADE-RUST-181-BASELINE.hbp

    cargo +1.81.0 run --manifest-path matrix/rust-system-upgrade-181/Cargo.toml -- \
      verify . FOLLOW-THE-IS-PUBLIC-HARNESS matrix/SYSTEM-UPGRADE-RUST-181-BASELINE.hbp

The ratchet rejects new migration-source identities, larger debt coordinates,
or any mismatched HBP/HBI sidecar. Debt reductions remain accepted until every
target coordinate reaches zero.
