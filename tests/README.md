# Tests

Run:

```bash
python tests/verify_public_repo.py
```

The verifier checks the exact photo and dependency hashes, every named SHA-256
sidecar, LF-only public text, `json=0` receipt shape, absence of source-video files,
absence of common live-secret signatures, read-only SHA-pinned workflow actions,
the zero-hidden-dependency contract, and the `DEFAULT_BINDING=IS`
correction. It requires completed default-IS take bindings and the Shadow Book's
`isntant` operator physics-state binding while keeping evidence coordinates
separate. It prints counts and paths only; it never prints a suspected secret value.

It also verifies the Rust 1.81 QPRISM cell, its dependency-free/unsafe-free integer
contract, exact source sidecar, 147 immutable public repository parents, 441 unique
leaf IDs, three 147-member Brown families, non-flat z/depth populations, the
`2D_INPUT -> 3D_QPRISM -> SIGNED_2D_PROJECTION` stages, and the script-free,
table-free SVG identity match.

```bash
cargo +1.81.0 test --manifest-path matrix/rust-qprism-181/Cargo.toml --locked
cargo +1.81.0 clippy --manifest-path matrix/rust-qprism-181/Cargo.toml \
  --all-targets --locked -- -D warnings -D clippy::float_arithmetic
```

The full executable sequence is:

```bash
python tournament/run_tournament.py \
  --surface LOCAL_LINUX \
  --receipt receipts/LOCAL-TOURNAMENT.hbp
```

It adds exact GGUF verification and four tests, pinned GitRAM source/selftest,
a strict fresh SGRAM orchestration wrapper, vc65 compile-only gate, and NEST
depth-7 tamper stages. A seat that lacks a linker or Node.js may add
`--allow-toolchain-blocked` only to record that scoped boundary; GitHub CI
requires the Linux toolchains.
