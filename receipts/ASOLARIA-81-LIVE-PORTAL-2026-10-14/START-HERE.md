# Asolaria 81 — live Host B / Host A cross-chat portal

**Stone 034 status: Host B's fresh nine-wave challenge is public. Host A has not responded yet.**

- Host B implementation: Node.js cyclic GF(2) polynomial, independent SHA-256 five-stage commitments.
- Host A implementation: Python 81x81 GF(2) transfer matrices, same WASM-seat SHA-256 witness file.
- Nine waves × all 81 seats = **729 expected blinded trials**; horizon **10,000,000,000,000 model steps** per trial.
- Exact challenge: [B-CHALLENGE.json](./B-CHALLENGE.json).
- B challenge SHA-256: `58e962036aa9033f00a54eea12ebadfb006293ce91014a3be9936df9010f28f2`.
- GitHub challenge commit: `529958e96b8298ba2d5c409144933257baab5f98`.
- Baseline global root: `8f4aa66cee354aa9479173d780eafcaac875954e9137544d4a053eca62dfed28`.
- Witness CSV SHA-256: `29b7fffd0042ffbe3de73a5ed5dce9e0f17de85ff8f8a0094b9bcf93f610121d`.
- The Python/Node offline protocol passed a **separate 162-trial rehearsal**, not the live challenge.

## Instructions for independent Host A (other ChatGPT session)

Ask the first chat for the eight-file kit `asolaria-81-live-portal-host-b-2026-10-14.zip`. Upload that zip as a file to the other ChatGPT session, extract it and use the local Python file `src/portal_a.py`:

```bash
python src/portal_a.py blind --challenge receipts/B-CHALLENGE.json --private-out MY-PENDING-SECRETS.json --out A-BLIND.json
```

IMPORTANT: Retain `MY-PENDING-SECRETS.json` privately in Host A's container. **Do not publish it or the revealed secrets until Host B publishes its ACK.** No Hugging Face tokens, account credentials or SSH keys are needed.

Publish only `A-BLIND.json` at:

`receipts/ASOLARIA-81-LIVE-PORTAL-2026-10-14/A-BLIND.json`

using the authenticated GitHub connector, then tell Host B's ChatGPT session to continue.

Host B will verify the blind count and unchanged baseline, publish `B-ACK.json`, and then instruct A to produce `A-REVEAL.json`. B will independently check every mutation, the five dependent stages, 171 rings, and the 81-bit far-future state and publish `B-VERIFY.json`. A will independently audit B's evidence as `A-VERIFY.json`.

The five laws cycle CA150, CA90, CA60, CA102, SHIFT over the nine waves. GitHub commits form an observable order of the stages.

## Scientific boundary

This is a *file-relayed, store-and-forward, independently implemented computational trial.* Distinct ChatGPT sessions are not guaranteed to be on physically separate computers. Neither this protocol nor agreement of hashes establishes faster-than-light signaling, gravitation, or quantum dynamics. The local evolution rules are constructed GF(2) cellular automata. The cryptographic root is an explicitly designed global dependency.

No secrets, API keys or long-lived tokens are in this portal.
