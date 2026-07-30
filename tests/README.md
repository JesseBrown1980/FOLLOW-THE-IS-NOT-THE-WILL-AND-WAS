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
