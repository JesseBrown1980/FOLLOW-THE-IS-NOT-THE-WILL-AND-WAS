# Public Law V17 — Timed 86,400 FLOWes ×3 ×3

Status: `OPERATOR_CANON | CODE_MEASURED_LIRIS_LOCAL | REAL_86400_RUN=RUNNING_LOCAL | SYSTEM_AFFIRMED=0`

This additive law keeps the completed aggregate parent day and the full folder
FLOWes measurement as separate evidence strata. The parent witness under
`matrix/timed-86400-parent-c8c3/` reached its nineteen scheduled checkpoints,
but its receipt correctly binds `full_x3_x3=0`. It is not renamed as this result.

## Sealed source and full shape

```text
SOURCE_HBP_SHA256 = 43300780cac2b85e3ed6cfa10398052f530ccbf76c43b404e650c26c9ed8b006
SOURCE_HBI_SHA256 = 9920d5cb2031d6453fba2d410e4b2f6e0136a4537fa6ea2ea9385c163503a28b
FOLDERS = 3536
FAMILIES = {BROWN, ANTI_BROWN, ANTI_ANTI_BROWN}
DIRECTIONS = {NEGATIVE, CENTRE, POSITIVE}
FINAL_CELLS = 3536 * 3 * 3 = 31824
```

Every folder-family source leaf expands through all three signed directions.
No family is flattened into a direction and `ANTI` is not relabeled as negative.

## HBI HBP SHA SH HASH

```text
CENTER_MEMBERSHIP = {HBI,HBP,SHA,SH,HASH}
TRAVERSAL = HBI -> HBP -> SH -> HASH -> SHA
COMMITMENTS_PER_CELL = 5
DOMAIN_SEPARATED = 1
SHA_EQUALS_HASH = 0
```

The five commitments are pairwise distinct for each of the 31,824 cells. `HASH`
binds the ordered spherical object including all five center members; `SHA` binds
final artifact bytes. Membership order and traversal order remain separate.

## Per-level reflection and time

```text
CHECKPOINT_SECONDS = {1,2,3,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768,65536,86400}
CHECKPOINTS = 19
AXES_PER_LEVEL = 3 * 3 = 9
RING_SUMMARIES = 19 * 9 = 171
REFLECTION_WINDOW_MAX = 60
TRANSFORM = 2D_TEXT -> 3D_SPHERICAL_TREE -> 2D_SIGNED_PROJECTION
```

Each family-direction axis chains its own prior ring. Every level applies
`SELF_REFLECT`, `COLLECT`, and `SELF_REDUCE` to at most sixty already observed
source commitments. Future text is not invented.

The production watch credits only whole seconds from `time.monotonic_ns()` in a
live SystemClock session. A restart begins from the last fully sealed checkpoint;
wall-clock gaps and uncheckpointed partial seconds receive zero credit. An
OS-held writer lock prevents two writers from crediting the same output. The
deterministic fake clock is a separately labeled CI fixture and cannot produce
`MEASURED_MONOTONIC_SESSION_SECONDS`.

## Public boundaries

```text
RAW_PRIVATE_PATHS = 0
MEDIA_BYTES_EMBEDDED = 0
REPOSITORY_BYTES_EMBEDDED = 0
CREDENTIALS = 0
NETWORK = 0
EXECUTION = 0
AUTHORITY = 0
PHYSICAL_ENERGY = 0
SYSTEM_AFFIRMED = 0
```

Windows and Ubuntu independently pass the focused corruption, lock-contention,
restart, time-label, SVG, GGUF, and commitment tests. A full 31,824-cell
deterministic bundle deep-verifies with identical hashes on both platforms. Those
results prove the code and deterministic fixture only. The real SystemClock watch
launched from public commit `cf4f760f943087d312894cef5a683d99fc0119df` at
`2026-07-31T18:29:52.4268838Z`; its launch receipt is
`receipts/LIRIS-FLOWES-X3-X3-86400-LAUNCH-2026-07-31.hbp`. `RUNNING_LOCAL` is
not completion. Final evidence exists only after the sealed journal reaches all
nineteen checkpoints through 86,400 seconds and the derived artifacts pass again.
