# The GitRAM doctrine

Origin: `research/pais-omega-floor1-v1/GITRAM.md` on branch
`agent/liris-pais-gitram-floor1-20260715` of
[HYPER-BECHS--the-third-set PR #42](https://github.com/JesseBrown1980/HYPER-BECHS--the-third-set/pull/42)
(commit `94718f8f78ea`, LIRIS seat, 2026-07-15). Text below restates that doctrine;
the origin file remains the canonical source.

## Doctrine

This lane distributes the one authorized floor across 27 isolated GitHub Actions
containers. Each container trains one complete, balanced all-byte Pais cube through the
full Cartesian schedule:

```
    8 reversible Ring-A representations
  × 10 forward/reverse variable-order predictor functions
  × 10 persistent recurrence epochs
  = 800 measured cells per cube
```

The six signed +R/−R/+N/−N/+Q/−Q pyramid directions are **exact replay gates, not extra
training multipliers**. Every cube artifact contains its own HBP receipt, SHA sidecars,
lossless base archive, and best trained replay chain.

The fan-in job downloads all 27 artifacts into one checkpoint tree and invokes the same
trainer in resume mode. It performs **no duplicate cube training**: all 27 checkpoints
are verified, the 11 PDFs are restored byte-exact, density is aggregated, and one
floor-one Omega center is sealed.

This GitRAM lane is independent of local RELIC and Liris processes. Higher floors, live
promotion, compression-record claims, and patent-physics validation remain held.

## Generalization (what makes a lane "GitRAM")

1. **Stateless cells.** Each container is a RAM cell: it owns one unit of work, compiles
   its tooling from in-repo source, shares no mutable state, and proves its own PASS.
2. **Artifacts are the memory bus.** Cell → artifact → fan-in is the only data path.
3. **All-or-nothing fan-in.** The seal requires every cell's checkpoint; a partial floor
   is never sealed.
4. **Receipts ride with the data.** HBP tuple rows + SHA-256 sidecars accompany every
   checkpoint and the sealed result (hot-path first, `json=0`; JSON is cold/debug only).
5. **Claims come from the owning gate.** Only the workflow's own concluded checks make a
   run green; everything else is scoped evidence.
