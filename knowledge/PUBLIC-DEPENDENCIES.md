# Public Dependency Ledger

Status: `MEASURED` on the Liris local public-Git mirrors, 2026-07-29.

## GitRAM

- Upstream: <https://github.com/JesseBrown1980/GitRAM>
- Commit: `be83ffb8bc13cb3995b52ce7a5fe6bdb9c5fcfa9`
- Embedded doctrine SHA-256:
  `fd78e586cd834b999b8d604169d4f4602ee33bf118eca8e9d7f63d682ede51e6`
- Embedded template SHA-256:
  `273b8c7714f6fc5a41f11d703065f5d36487690006a0cc492b6509988d474baf`

The doctrine defines stateless cells, artifacts as the memory bus, all-or-nothing
fan-in, HBP receipts, and the owning workflow as the green gate. The template is a
template—not proof that a workflow ran here.

## NEST

- Upstream:
  <https://github.com/JesseBrown1980/N-Nest-Prime-INFINITE-SELF-REFLECT-AGENTS-NESTED>
- Commit: `d37ee2f4cd21a2b55d5b2c6d8d0429acf3d9d753`
- Embedded verifier SHA-256:
  `5028de41315dc08557c13e601611e2f0da69e9edcbdd2e42db043dee0ccbcc89`

The dependency-free Node verifier builds the depth-7 binary NEST (255 nodes, two
PIDs per node) and injects one fault at every depth 1 through 7. Its generated HBP
receipt is runtime evidence only when the verifier actually runs.

## SGRAM and vc65

- Upstream: <https://github.com/JesseBrown1980/Algorithms-of-Asolaria>
- Commit: `a94abccd93b9bd42724840eaf26924a3db683d2a`
- Source branch at intake: `liris/rime-omega-rebuild-20260723`
- SGRAM SHA-256:
  `01a9372c0bcb9297b18af78ed83aa0586b60130fb36299e6dc919e69ba977dcc`
- Historical upstream-intake vc65 SHA-256:
  `64ae366fd87b71a21dde64e9156b997eb44c6d1743e2b944a4a63c492b56f94b`
- Active public Rust 1.81 integer-only vc65 SHA-256:
  `4392ab92314563cbbd986d54cc16c01a77b46e9935c95483e26402551446b10e`
- Upstream MIT license SHA-256:
  `e994f1997f8afa963389779b6c51a2cc3ac01edbc78a90915b6c43097ec68809`

SGRAM uses deterministic contiguous shards, per-shard byte-restore receipts, and
all-or-nothing fan-in. The embedded Rust codec is standard-library-only source. The
codec binary is built from that source; no private binary is required.

## Contract

```text
REQUIRED_HIDDEN_DEPENDENCIES=0
PINNED_SOURCE_FILES=5
PINNED_LICENSE_FILES=1
```

The public runtimes (`git`, Node.js, Python, Rust, and GitHub Actions where used)
are toolchain prerequisites, not hidden models or secret decoder state.

No license file was present at the pinned GitRAM or NEST root snapshot during this
measurement; this ledger does not invent one. The Algorithms files retain their
embedded MIT license.
