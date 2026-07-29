#!/usr/bin/env python3
"""
sgram_chain.py — LOCAL SGRAM chain (streaming GitRAM, one seat). Operator: Jesse
Daniel Brown, 2026-07-21.

Rides a big corpus as a CHAIN OF WAVES (deterministic contiguous shards). Each
shard is compressed + self-verified (byte-exact SHA restore) by the in-repo codec,
its RECEIPT written to disk (the checkpoint). If the container restarts mid-chain,
re-running RESUMES from the last sealed shard instead of restarting the whole run —
the receipts are the memory bus (GitRAM doctrine, local seat).

Fan-in: require ALL shards PASS, sum byte-exact payloads + the decoder source, seal
ONE bpc for the whole corpus.

HONEST NOTE (measured, not hidden): independent shards cold-start the model per
shard, so the sealed total is LARGER than one monolithic run (+~6% at 8 shards /
10 MB, per sgram-compress.yml). The seal reports the true SHARDED total; it is a
conservative SCREEN, not the monolithic Hutter number. The measurement is referee.

Usage: sgram_chain.py <corpus> <shards> <k> <codec_bin> <decoder_src> <receipt_dir>
"""
import sys, os, subprocess, hashlib, re

def sha16(b): return hashlib.sha256(b).hexdigest()[:16]

def main():
    corpus, shards, k = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    codec, dec_src, rdir = sys.argv[4], sys.argv[5], sys.argv[6]
    os.makedirs(rdir, exist_ok=True)
    sz = os.path.getsize(corpus)
    chunk = (sz + shards - 1) // shards
    print(f"=== SGRAM CHAIN (local seat) — ride {sz:,} B as {shards} waves, order-{k} ===")
    print(f"corpus={corpus}  codec={os.path.basename(codec)}  decoder_src={dec_src}\n")

    for c in range(shards):
        rpath = os.path.join(rdir, f"receipt-{c:03d}.txt")
        off = c * chunk
        length = min(chunk, sz - off)
        if os.path.exists(rpath) and 'restore=OK' in open(rpath).read():
            print(f"wave {c:>3}/{shards}: RESUMED (receipt exists, PASS) — skipped")
            continue
        # cut this wave's shard deterministically (contiguous [off, off+len))
        with open(corpus, 'rb') as f:
            f.seek(off); shard = f.read(length)
        spath = os.path.join(rdir, f"shard-{c:03d}.bin")
        with open(spath, 'wb') as f: f.write(shard)
        res = subprocess.run([codec, spath, k], capture_output=True, text=True)
        line = (res.stdout + res.stderr).strip()
        if 'restore=OK' not in line:
            print(f"wave {c:>3}: FAIL — {line}"); sys.exit(1)
        with open(rpath, 'w') as f: f.write(line + f" shard_sha={sha16(shard)}\n")
        os.remove(spath)                                  # don't hoard shard bytes
        pay = int(re.search(r'payload=(\d+)', line).group(1))
        print(f"wave {c:>3}/{shards}: PASS  bytes={length:,}  payload={pay:,}  "
              f"bpc={pay*8/length:.4f}  sha={sha16(shard)}")

    # ---- FAN-IN: require ALL, verify PASS, sum byte-exact, seal one bpc ----
    pay_sum = 0; n_sum = 0; all_ok = True
    for c in range(shards):
        r = open(os.path.join(rdir, f"receipt-{c:03d}.txt")).read()
        if 'restore=OK' not in r: all_ok = False; break
        pay_sum += int(re.search(r'payload=(\d+)', r).group(1))
        n_sum   += int(re.search(r'N=(\d+)', r).group(1))
    dec = os.path.getsize(dec_src)
    total = pay_sum + dec
    print(f"\nSGRAM SEAL: shards={shards} corpus_bytes={n_sum:,} payload_sum={pay_sum:,} "
          f"decoder={dec} total={total:,}")
    print(f"  sealed bpc_total = {total*8/n_sum:.4f}   (SHARDED — conservative screen)")
    print(f"  +~6% cold-start overhead is REAL and included; monolithic single-stream")
    print(f"  would be LOWER. This is a screen, not the monolithic Hutter number.")
    print(f"  all shards byte-exact (restore=OK): {all_ok}")

if __name__ == "__main__":
    main()
