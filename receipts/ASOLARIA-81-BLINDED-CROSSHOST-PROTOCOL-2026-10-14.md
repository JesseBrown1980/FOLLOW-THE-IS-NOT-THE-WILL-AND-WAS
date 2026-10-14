# Asolaria Rainbow-81 — blinded cross-host protocol, Stone 024–033

**Evidence class: LOCAL TWO-PROCESS DRY RUN.** This document deliberately does **not** claim that two independent physical hosts have been tested.

Date: 2026-10-14 UTC.

## Measured local run
- Two independent implementations on one Linux host: Python 81×81 GF(2) matrix exponentiation (host A) and Node.js cyclic-polynomial GF(2) exponentiation (host B).
- Nine waves × 81 mutated source seats = **729/729 independent agreements** on full future states and domain-separated hash roots.
- Each wave advances a known, constructed 81-bit evolution law **10,000,000,000,000 model steps**, alternating CA150, CA90, CA60, CA102 and reversible cyclic SHIFT.
- Blinded phase: B issues a fresh 256-bit challenge; A sends SHA-256 precommit only, and B's cached baseline remains unchanged. Reveal phase: A provides the seat and freshly sampled 256-bit mutation; B validates and independently recomputes.
- All 405 derived cell-stage commitments and 171 constructed ring commitments change after the **shared source HBP checksum is explicitly recomputed**.
- Wrong-secret, out-of-order-reveal and stale-challenge replay negative controls: **rejected**.
- Locally observed median A-side reveal roundtrip: **3.340082 ms**; A compute: **1.937221 ms**; B compute: **2.834164 ms**. These are local CPU/loopback timings, not remote propagation speeds.

## Scope boundaries
- Not yet run on distinct physical computers. No synchronized one-way timing, gravity dynamics, natural quantum evolution, or faster-than-light communication measured.
- SHA commitments change due to a **designed dependency**. The evolution rule—not SHA alone—computes future model states.
- The constructed canonical HBI → HBP → SH → HASH → SHA calculation uses stage labels from the upstream repository but must not be conflated with all upstream implementations.
- A physical cross-host run requires two independently controlled computers using an SSH tunnel, preserving each host's logs; hostnames alone do not prove physical independence.

## Sealed evidence pointers
- Local Git commit preserving prior stones: `75c20133752983aa48b7de8a1dac9bcb0777205e` (parent `ee30530a335a5605a82b6142624aadb6ab7d9350`).
- `STONE-033-cross-host-summary.json` SHA-256: `23e59ab318299f2601802997349eeb14a4ad1aaba085d8e59e27a0e65ec4222a`
- `CROSS-HOST-INDEX.hbi` SHA-256: `c200785d4c71f48aceb5b68d6b91c5d1ca210294d0e8436a1f70c2e70d55a050`
- `CROSS-HOST-MEASUREMENTS.hbp` SHA-256: `0d9a2c8c7893108d2b0453638350a4b421ba9dca3273e0617eb8f5de885897a9`
- Full standalone source/receipt ZIP SHA-256: `1121c40d0dc3e28a68f314a04d1ca6b1061a2a9403d52e380f93e7d51078c3db`.
- Full chronological Git bundle SHA-256: `45397f13c557d07ba201bc3082a236d88522032955c0ff009702d9e0faf32846`.
- Intended full artifact mirror: https://huggingface.co/Jessedbrown/asolaria-wasm81-rainbow-audit (**full Stone 024–033 release upload not yet confirmed**).

## Source references
- [81-seat WASM source](https://github.com/JesseBrown1980/one-click/blob/main/index.html)
- [Five-stage operator pointer](https://github.com/JesseBrown1980/FOLLOW-THE-IS-NOT-THE-WILL-AND-WAS/blob/main/knowledge/LIRIS-SH-PRELIGHT-PUBLIC-POINTER-2026-08-04.hbp)
- [Golden-angle coordinate reference](https://github.com/JesseBrown1980/Be-infinitly-express-spherically-free/blob/main/index.html)

**No Hugging Face authentication tokens or API keys are included in this file.**
