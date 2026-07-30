# Public GitRAM / SGRAM / NEST Tournament

This directory is the dependency-free executable sequence for the public repository.
It tests actual pinned bytes and emits deterministic `json=0` HBP stage rows.

## Fixed sequence

1. Public repository hash, LF, secret-pattern, media, and hidden-dependency gate.
2. Exact 3,174-byte Double Rainbow GGUF verifier.
3. Exactly four committed GGUF regression tests.
4. Pinned GitRAM doctrine, template, and executable Path-3 bridge byte/contract gate.
5. Compile and run the real GitRAM Path-3 bridge `selftest`.
6. Pinned SGRAM/Streaming-GitRAM source gate.
7. Record the raw SGRAM resume-binding weakness as `PENDING_UPSTREAM_FIX`.
8. Run a fresh three-wave SGRAM orchestration roundtrip with strict wrapper checks
   over every expected range, `N`, shard SHA prefix, and summed corpus length. The
   explicitly named identity test codec makes this an orchestration test, not a
   compression benchmark.
9. Compile the pinned `vc65.rs`; its multi-gigabyte runtime is not executed here.
10. Run the NEST depth-7 clean case and one tamper at each depth in a temporary
    directory.

Run from the repository root:

```bash
python tournament/run_tournament.py \
  --surface LOCAL_LINUX \
  --receipt receipts/LOCAL-TOURNAMENT.hbp
```

Use `--allow-toolchain-blocked` only for a seat-scoped measurement where a missing
linker or runtime is being recorded rather than hidden. GitHub CI does not use that
flag.

## Name and evidence boundary

The pinned Algorithms source itself says `SGRAM` is `Streaming GitRAM`. That exact
implementation is tested here. A separately named `sGitRAM` source was not found in
the searched archaeology or exact owner GitHub code surface, so it remains:

```text
SGITRAM_NAMED_IMPLEMENTATION = PENDING_OWNING_SOURCE
SGITRAM_IS_SGRAM             = NOT_ASSUMED
```

The raw upstream SGRAM resume path accepts an existing `restore=OK` receipt without
binding it to the current corpus range, `k`, codec, or decoder, and fan-in does not
require summed `N` to equal the corpus size. The tournament therefore never labels
that raw path green. Its passing local stage always starts with a nonexistent receipt
directory and independently checks each expected shard and total.

## Current Asolaria gate

The tournament carries the parent preflight boundary from 2026-07-29:

```text
fabric/canon = STALE_FALLBACK
RECAL        = UNAVAILABLE
Liris BEHCS  = HEALTH_LIVE_ONLY
SYSTEM_AFFIRMED = 0
```

Local and GitHub source/test results are `MEASURED` only for their named surfaces.
They are not promoted into a live-system absorption claim.

`REQUIRED_HIDDEN_DEPENDENCIES=0`. No source-video bytes, account credentials,
private paths, private keys, health identifiers, or secret values enter a receipt.
Child processes receive the ordinary toolchain environment after variables whose
names indicate tokens, secrets, passwords, API/private keys, cookies, or credentials
have been removed.
