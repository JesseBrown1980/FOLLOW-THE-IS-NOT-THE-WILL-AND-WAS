// Pais Path-3 bridge — LEVEL 2 floor over THEIR constitution bundle, their way.
// Corpus = the sealed Floor-1 trilateral preparation bundle (deterministic, fire=0),
// cut into 27 SHA-pinned cubes + 6 apex axis-traversals + 1 timing-free junction = 34
// bodies. NEW parts made executable here:
//   LANGUAGE_GENESIS  — every body speaks its OWN native glyph language: a 1024-glyph
//                       codebook permutation seeded by the body's SHA (never English);
//                       translation = the receipted permutation, exactly reversible.
//   OMNISUBMIT        — every body seals a domain-separated, length-prefixed OmniSubmit
//                       tuple leaf; the floor seals the epoch root
//                       Omega_e = H(D_Omega || e || Omega_{e-1} || sorted leaves).
// Publication-held constraint honored: this lane runs on local silicon; only
// content-free receipts (hashes + counts) leave the machine. Timing-free leaf law.
// Standing prediction receipted: by the bijection-invariance theorem, per-body
// codebooks change learned CONTENT (payload digests) but scalar gains only by
// tie-break noise. Higher floors HELD. No record claims.

use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Instant;

type AnyResult<T> = Result<T, String>;

const BODY_COUNT: usize = 34;
const BASE_COUNT: usize = 27;
const EPOCHS: usize = 10;
const BITS: u32 = 10;
const A_NAMES: [&str; 8] = [
    "G1024_FORWARD_IDENTITY",
    "G1024_REVERSE_GLYPHS",
    "G1024_FORWARD_XOR_DELTA",
    "G1024_REVERSE_ROTATE_BITS",
    "G1024_HALF_SWAP",
    "G1024_BLOCK_REVERSE",
    "G1024_NESTED_EVEN_ODD",
    "G1024_QPRISM_PRIME_BLOCK",
];
const B_DIRECTIONS: [&str; 2] = ["BLACK_FORWARD", "WHITE_REVERSE"];
const APEX_NAMES: [&str; 6] = ["+X", "-X", "+Y", "-Y", "+Z", "-Z"];

// ---------- sha256 / hex / receipts ----------

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ];
    let mut msg = data.to_vec();
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    let mut h: [u32; 8] = [
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
    ];
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i*4..i*4+4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let (mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut hh) =
            (h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh=g; g=f; f=e; e=d.wrapping_add(t1); d=c; c=b; b=a; a=t1.wrapping_add(t2);
        }
        h[0]=h[0].wrapping_add(a); h[1]=h[1].wrapping_add(b);
        h[2]=h[2].wrapping_add(c); h[3]=h[3].wrapping_add(d);
        h[4]=h[4].wrapping_add(e); h[5]=h[5].wrapping_add(f);
        h[6]=h[6].wrapping_add(g); h[7]=h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() { out[i*4..i*4+4].copy_from_slice(&v.to_be_bytes()); }
    out
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len()*2);
    for &b in bytes { s.push(H[(b>>4) as usize] as char); s.push(H[(b&15) as usize] as char); }
    s
}

fn sha_hex(data: &[u8]) -> String { hex(&sha256(data)) }

fn parse_fields(line: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for field in line.split('|').skip(1) {
        if let Some((k,v)) = field.split_once('=') { out.insert(k.to_string(), v.to_string()); }
    }
    out
}

fn write_lf(path: &Path, text: &str) -> AnyResult<()> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    fs::write(path, normalized.as_bytes()).map_err(|e| format!("write {}: {}", path.display(), e))
}

fn write_sidecar(path: &Path) -> AnyResult<String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let digest = sha_hex(&bytes);
    let name = path.file_name().unwrap().to_string_lossy();
    write_lf(&PathBuf::from(format!("{}.sha256", path.display())), &format!("{}  {}\n", digest, name))?;
    Ok(digest)
}

fn check_sidecar(path: &Path) -> AnyResult<String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    let digest = sha_hex(&bytes);
    let side = fs::read_to_string(PathBuf::from(format!("{}.sha256", path.display())))
        .map_err(|e| format!("sidecar {}: {}", path.display(), e))?;
    let expected = side.split_whitespace().next().unwrap_or("");
    if expected != digest { return Err(format!("sidecar mismatch {}", path.display())); }
    Ok(digest)
}

fn pid8(label: &str) -> String { sha_hex(label.as_bytes())[..16].to_string() }

// ---------- LZ1 ----------

fn flush_literals(out:&mut Vec<u8>,lits:&mut Vec<u8>) {
    let mut at=0usize;
    while at<lits.len() { let n=(lits.len()-at).min(u16::MAX as usize); out.push(0); out.extend_from_slice(&(n as u16).to_le_bytes()); out.extend_from_slice(&lits[at..at+n]); at+=n; }
    lits.clear();
}

fn lz_compress(data:&[u8])->Vec<u8> {
    let mut out=b"LZ1\0".to_vec(); out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    let mut last:HashMap<u32,usize>=HashMap::new(); let mut lits=Vec::new(); let mut i=0usize;
    while i<data.len() {
        let key=if i+2<data.len(){Some(((data[i] as u32)<<16)|((data[i+1] as u32)<<8)|data[i+2] as u32)}else{None};
        let mut best=0usize; let mut offset=0usize;
        if let Some(k)=key { if let Some(&p)=last.get(&k) { let off=i-p; if off>0&&off<=u16::MAX as usize { let max=(data.len()-i).min(u16::MAX as usize); while best<max&&data[p+best]==data[i+best]{best+=1;} if best>=4{offset=off;} } } }
        if best>=4 {
            flush_literals(&mut out,&mut lits); out.push(1); out.extend_from_slice(&(offset as u16).to_le_bytes()); out.extend_from_slice(&(best as u16).to_le_bytes());
            for pos in i..i+best { if pos+2<data.len(){let k=((data[pos] as u32)<<16)|((data[pos+1] as u32)<<8)|data[pos+2] as u32; last.insert(k,pos);} }
            i+=best;
        } else {
            if let Some(k)=key {last.insert(k,i);} lits.push(data[i]); i+=1; if lits.len()==u16::MAX as usize{flush_literals(&mut out,&mut lits);}
        }
    }
    flush_literals(&mut out,&mut lits); out
}

fn lz_decompress(data:&[u8])->AnyResult<Vec<u8>> {
    if data.len()<12||&data[..4]!=b"LZ1\0" {return Err("bad LZ1 header".into());}
    let want=u64::from_le_bytes(data[4..12].try_into().unwrap()) as usize; let mut at=12usize; let mut out=Vec::with_capacity(want);
    while at<data.len()&&out.len()<want {
        let tag=data[at]; at+=1;
        if tag==0 { if at+2>data.len(){return Err("short literal".into());} let n=u16::from_le_bytes(data[at..at+2].try_into().unwrap()) as usize; at+=2; if at+n>data.len(){return Err("literal overflow".into());} out.extend_from_slice(&data[at..at+n]); at+=n; }
        else if tag==1 { if at+4>data.len(){return Err("short match".into());} let off=u16::from_le_bytes(data[at..at+2].try_into().unwrap()) as usize; let n=u16::from_le_bytes(data[at+2..at+4].try_into().unwrap()) as usize; at+=4; if off==0||off>out.len(){return Err("bad match offset".into());} for _ in 0..n {let b=out[out.len()-off];out.push(b);} }
        else {return Err("bad LZ1 tag".into());}
    }
    if out.len()!=want {return Err("LZ1 length mismatch".into());} Ok(out)
}

// ---------- predictor (B-bit symbols) ----------

#[derive(Clone, PartialEq, Eq)]
struct BestState { total: u32, best_symbol: u16, best_count: u32 }

#[derive(Clone, PartialEq, Eq)]
struct PredictorModel {
    bits: u32,
    order: u8,
    direction: u8,
    counts: HashMap<(u64, u16), u32>,
    best: HashMap<u64, BestState>,
    commit: [u8; 32],
    epochs: u32,
}

struct Metrics {
    predictions: u64,
    top1_correct: u64,
    unseen_contexts: u64,
    novel_pairs: u64,
    confident_blunders: u64,
}

impl PredictorModel {
    fn new(bits: u32, order: u8, direction: u8) -> Self {
        let mut domain=b"PAIS-PREDICTOR-STATE-V2|".to_vec();
        domain.push(bits as u8); domain.push(order); domain.push(direction);
        Self{bits,order,direction,counts:HashMap::new(),best:HashMap::new(),commit:sha256(&domain),epochs:0}
    }
    fn mask(&self)->u64 { (1u64 << (self.order as u32*self.bits))-1 }
    fn key(&self,ctx:u64,seen:usize)->u64 {
        let n=seen.min(self.order as usize) as u64;
        ctx | (n<<50) | ((self.order as u64)<<56)
    }
    fn predict(&self,key:u64)->(u16,u32,u32) {
        self.best.get(&key).map(|s|(s.best_symbol,s.best_count,s.total)).unwrap_or((0,0,0))
    }
    fn update(&mut self,key:u64,sym:u16)->bool {
        let count=self.counts.entry((key,sym)).or_insert(0); let novel=*count==0; *count+=1; let nc=*count;
        let state=self.best.entry(key).or_insert(BestState{total:0,best_symbol:0,best_count:0});
        state.total=state.total.saturating_add(1);
        if nc>state.best_count || (nc==state.best_count && sym<state.best_symbol) { state.best_symbol=sym; state.best_count=nc; }
        novel
    }
    fn finish_epoch(&mut self,seq:&[u16],m:&Metrics) {
        let packed=pack_glyphs(seq,self.bits);
        let mut b=Vec::new(); b.extend_from_slice(&self.commit); b.extend_from_slice(&sha256(&packed));
        b.extend_from_slice(&(self.epochs+1).to_le_bytes()); b.extend_from_slice(&m.predictions.to_le_bytes());
        b.extend_from_slice(&m.top1_correct.to_le_bytes()); b.extend_from_slice(&m.unseen_contexts.to_le_bytes());
        b.extend_from_slice(&m.novel_pairs.to_le_bytes()); b.extend_from_slice(&(self.counts.len() as u64).to_le_bytes());
        self.commit=sha256(&b); self.epochs+=1;
    }
    fn encode(&mut self,seq:&[u16])->(Vec<u16>,Metrics) {
        let mut residual=Vec::with_capacity(seq.len()); let mut ctx=0u64; let mut seen=0usize;
        let mut m=Metrics{predictions:0,top1_correct:0,unseen_contexts:0,novel_pairs:0,confident_blunders:0};
        let mask=self.mask();
        for &sym in seq {
            let key=self.key(ctx,seen); let (pred,best_count,total)=self.predict(key);
            if total==0 { m.unseen_contexts+=1; } else { m.predictions+=1; if pred==sym {m.top1_correct+=1;} else if (best_count as u64)*10 >= (total as u64)*9 {m.confident_blunders+=1;} }
            residual.push(sym^pred); if self.update(key,sym) {m.novel_pairs+=1;}
            ctx=((ctx<<self.bits)|(sym as u64))&mask; seen+=1;
        }
        self.finish_epoch(seq,&m); (residual,m)
    }
    fn decode(&mut self,residual:&[u16])->(Vec<u16>,Metrics) {
        let mut seq=Vec::with_capacity(residual.len()); let mut ctx=0u64; let mut seen=0usize;
        let mut m=Metrics{predictions:0,top1_correct:0,unseen_contexts:0,novel_pairs:0,confident_blunders:0};
        let mask=self.mask();
        for &r in residual {
            let key=self.key(ctx,seen); let (pred,best_count,total)=self.predict(key); let sym=r^pred;
            if total==0 { m.unseen_contexts+=1; } else { m.predictions+=1; if pred==sym {m.top1_correct+=1;} else if (best_count as u64)*10 >= (total as u64)*9 {m.confident_blunders+=1;} }
            if self.update(key,sym) {m.novel_pairs+=1;}
            seq.push(sym); ctx=((ctx<<self.bits)|(sym as u64))&mask; seen+=1;
        }
        self.finish_epoch(&seq,&m); (seq,m)
    }
}

// ---------- glyph layer ----------

fn bytes_to_glyphs(bytes:&[u8], bits:u32)->Vec<u16> {
    let total_bits=bytes.len()*8;
    let count=(total_bits+bits as usize-1)/bits as usize;
    let mut out=Vec::with_capacity(count);
    let mut acc:u32=0; let mut nb:u32=0;
    for &b in bytes {
        acc=(acc<<8)|(b as u32); nb+=8;
        while nb>=bits { nb-=bits; out.push(((acc>>nb)&((1<<bits)-1)) as u16); }
    }
    if nb>0 { out.push(((acc<<(bits-nb))&((1<<bits)-1)) as u16); }
    out
}

fn glyphs_to_bytes(glyphs:&[u16], bits:u32, native_len:usize)->Vec<u8> {
    let mut out=Vec::with_capacity(native_len+2);
    let mut acc:u32=0; let mut nb:u32=0;
    for &g in glyphs {
        acc=(acc<<bits)|(g as u32); nb+=bits;
        while nb>=8 { nb-=8; out.push(((acc>>nb)&0xff) as u8); }
    }
    if nb>0 { out.push(((acc<<(8-nb))&0xff) as u8); }
    out.truncate(native_len);
    out
}

fn pack_glyphs(glyphs:&[u16], bits:u32)->Vec<u8> {
    let mut out=Vec::with_capacity((glyphs.len()*bits as usize+7)/8);
    let mut acc:u32=0; let mut nb:u32=0;
    for &g in glyphs {
        acc=(acc<<bits)|(g as u32); nb+=bits;
        while nb>=8 { nb-=8; out.push(((acc>>nb)&0xff) as u8); }
    }
    if nb>0 { out.push(((acc<<(8-nb))&0xff) as u8); }
    out
}

fn unpack_glyphs(bytes:&[u8], bits:u32, count:usize)->Vec<u16> {
    let mut out=Vec::with_capacity(count);
    let mut acc:u32=0; let mut nb:u32=0;
    for &b in bytes {
        acc=(acc<<8)|(b as u32); nb+=8;
        while nb>=bits { if out.len()==count {break;} nb-=bits; out.push(((acc>>nb)&((1<<bits)-1)) as u16); }
        if out.len()==count {break;}
    }
    out
}

fn rev_bits(v:u16, n:u32)->u16 {
    let mut out=0u16;
    for i in 0..n { if v&(1<<i)!=0 { out|=1<<(n-1-i); } }
    out
}

fn g_r(data:&[u16])->Vec<u16> { data.iter().rev().copied().collect() }
fn g_n(data:&[u16], bits:u32)->Vec<u16> {
    let half=bits/2; let hm=(1u16<<half)-1;
    data.iter().map(|&g| ((g&hm)<<half)|(g>>half)).collect()
}
fn g_q(data:&[u16], bits:u32)->Vec<u16> {
    let half=bits/2; let hm=(1u16<<half)-1;
    data.iter().map(|&g| (rev_bits(g>>half,half)<<half)|rev_bits(g&hm,half)).collect()
}

fn geometry_view_glyphs(data:&[u16], mask:u8, bits:u32)->Vec<u16> {
    let mut out=data.to_vec();
    if mask&1 != 0 { out=g_r(&out); }
    if mask&2 != 0 { out=g_n(&out,bits); }
    if mask&4 != 0 { out=g_q(&out,bits); }
    out
}

fn group_gate_glyphs(data:&[u16], bits:u32)->(bool, Vec<String>, String) {
    let rr=g_r(&g_r(data))==*data;
    let nn=g_n(&g_n(data,bits),bits)==*data;
    let qq=g_q(&g_q(data,bits),bits)==*data;
    let rn=g_r(&g_n(data,bits))==g_n(&g_r(data),bits);
    let rq=g_r(&g_q(data,bits))==g_q(&g_r(data),bits);
    let nq=g_n(&g_q(data,bits),bits)==g_q(&g_n(data,bits),bits);
    let mut views=Vec::new();
    let mut uniq=HashSet::new();
    for m in 0..8 { let v=geometry_view_glyphs(data,m,bits); let h=sha_hex(&pack_glyphs(&v,bits)); uniq.insert(h.clone()); views.push(h); }
    let rnq=geometry_view_glyphs(data,7,bits);
    let total:Vec<u16>=data.iter().rev().map(|&g| rev_bits(g,bits)).collect();
    let total_ok=rnq==total;
    (rr&&nn&&qq&&rn&&rq&&nq&&uniq.len()==8&&total_ok, views, format!("squares={},{},{}|commutators={},{},{}|distinct={}|rnq_total={}", u8::from(rr),u8::from(nn),u8::from(qq),u8::from(rn),u8::from(rq),u8::from(nq),uniq.len(),u8::from(total_ok)))
}

fn xor_delta_glyphs(data:&[u16])->Vec<u16> {
    if data.is_empty() { return Vec::new(); }
    let mut out=Vec::with_capacity(data.len()); out.push(data[0]);
    for i in 1..data.len() { out.push(data[i]^data[i-1]); }
    out
}
fn xor_undelta_glyphs(data:&[u16])->Vec<u16> {
    if data.is_empty() { return Vec::new(); }
    let mut out=Vec::with_capacity(data.len()); out.push(data[0]);
    for i in 1..data.len() { let g=data[i]^out[i-1]; out.push(g); }
    out
}
fn rotate_left_glyph(g:u16, bits:u32)->u16 { let m=(1u16<<bits)-1; ((g<<1)|(g>>(bits-1)))&m }
fn rotate_right_glyph(g:u16, bits:u32)->u16 { let m=(1u16<<bits)-1; ((g>>1)|((g&1)<<(bits-1)))&m }
fn block_reverse_glyphs(data:&[u16], block:usize)->Vec<u16> {
    let mut out=Vec::with_capacity(data.len());
    for c in data.chunks(block) { out.extend(c.iter().rev()); }
    out
}
fn even_odd_glyphs(data:&[u16])->Vec<u16> {
    data.iter().step_by(2).chain(data.iter().skip(1).step_by(2)).copied().collect()
}
fn undo_even_odd_glyphs(data:&[u16])->Vec<u16> {
    let even=(data.len()+1)/2; let mut out=vec![0u16;data.len()];
    for i in 0..even { out[i*2]=data[i]; }
    for i in even..data.len() { out[(i-even)*2+1]=data[i]; }
    out
}
fn qprism_order_glyphs(nblocks:usize, source_sha:&[u8;32])->Vec<usize> {
    let mut keyed:Vec<([u8;32],usize)>=(0..nblocks).map(|i| {
        let mut seed=b"QPRISM_PRIME_BLOCK_GLYPH_V2|257|".to_vec();
        seed.extend_from_slice(source_sha); seed.extend_from_slice(&(i as u64).to_le_bytes());
        (sha256(&seed),i)
    }).collect();
    keyed.sort_by(|a,b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    keyed.into_iter().map(|x|x.1).collect()
}
fn qprism_glyphs(data:&[u16], source_sha:&[u8;32])->Vec<u16> {
    let block=257usize; let n=data.len()/block; let order=qprism_order_glyphs(n,source_sha);
    let mut out=Vec::with_capacity(data.len());
    for orig in order { out.extend_from_slice(&data[orig*block..(orig+1)*block]); }
    out.extend_from_slice(&data[n*block..]); out
}
fn undo_qprism_glyphs(data:&[u16], source_sha:&[u8;32])->Vec<u16> {
    let block=257usize; let n=data.len()/block; let order=qprism_order_glyphs(n,source_sha);
    let mut out=vec![0u16;data.len()];
    for (pos,orig) in order.into_iter().enumerate() {
        out[orig*block..(orig+1)*block].copy_from_slice(&data[pos*block..(pos+1)*block]);
    }
    out[n*block..].copy_from_slice(&data[n*block..]); out
}

fn a_apply_glyphs(index:usize, data:&[u16], bits:u32, source_sha:&[u8;32])->Vec<u16> {
    match index {
        0=>data.to_vec(),
        1=>g_r(data),
        2=>xor_delta_glyphs(data),
        3=>data.iter().rev().map(|&g|rotate_left_glyph(g,bits)).collect(),
        4=>g_n(data,bits),
        5=>block_reverse_glyphs(data,256),
        6=>even_odd_glyphs(data),
        7=>qprism_glyphs(data,source_sha),
        _=>unreachable!(),
    }
}
fn a_inverse_glyphs(index:usize, data:&[u16], bits:u32, source_sha:&[u8;32])->Vec<u16> {
    match index {
        0=>data.to_vec(),
        1=>g_r(data),
        2=>xor_undelta_glyphs(data),
        3=>data.iter().map(|&g|rotate_right_glyph(g,bits)).rev().collect(),
        4=>g_n(data,bits),
        5=>block_reverse_glyphs(data,256),
        6=>undo_even_odd_glyphs(data),
        7=>undo_qprism_glyphs(data,source_sha),
        _=>unreachable!(),
    }
}

// ---------- LANGUAGE_GENESIS: per-body native codebook ----------

fn language_codebook(body_sha:&[u8;32], bits:u32)->(Vec<u16>,Vec<u16>,String) {
    let n=1usize<<bits;
    let mut keyed:Vec<([u8;32],usize)>=(0..n).map(|g| {
        let mut seed=b"LANGUAGE_GENESIS_V1|".to_vec();
        seed.extend_from_slice(body_sha);
        seed.extend_from_slice(&(g as u64).to_le_bytes());
        (sha256(&seed),g)
    }).collect();
    keyed.sort_by(|a,b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut perm=vec![0u16;n];
    for (new,(_,old)) in keyed.into_iter().enumerate() { perm[old]=new as u16; }
    let mut inv=vec![0u16;n];
    for (old,&new) in perm.iter().enumerate() { inv[new as usize]=old as u16; }
    let mut perm_bytes=Vec::with_capacity(n*2);
    for &p in &perm { perm_bytes.extend_from_slice(&p.to_le_bytes()); }
    let codebook_sha=sha_hex(&perm_bytes);
    (perm,inv,codebook_sha)
}

fn speak(glyphs:&[u16], perm:&[u16])->Vec<u16> { glyphs.iter().map(|&g| perm[g as usize]).collect() }

// ---------- OMNISUBMIT: domain-separated, length-prefixed tuple + epoch root ----------

fn canonical_encode(fields:&[(&str,&str)])->Vec<u8> {
    let mut out=Vec::new();
    for (k,v) in fields {
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(v.as_bytes());
    }
    out
}

fn omnisubmit_leaf(fields:&[(&str,&str)])->String {
    let mut msg=b"PATH3-LEAF-V1\0".to_vec();
    msg.extend_from_slice(&canonical_encode(fields));
    sha_hex(&msg)
}

fn omnisubmit_epoch_root(epoch:u64, parent_hex:&str, leaves:&[String])->String {
    let mut sorted=leaves.to_vec(); sorted.sort();
    let mut msg=b"PATH3-OMEGA-V1\0".to_vec();
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(&(parent_hex.len() as u32).to_le_bytes());
    msg.extend_from_slice(parent_hex.as_bytes());
    for l in &sorted {
        msg.extend_from_slice(&(l.len() as u32).to_le_bytes());
        msg.extend_from_slice(l.as_bytes());
    }
    sha_hex(&msg)
}

// ---------- bundle corpus -> 34 bodies ----------

struct Corpus { data: Vec<u8>, sha: String, files: Vec<(String,String,usize)> }

fn load_bundle(dir:&Path)->AnyResult<Corpus> {
    let mut names=Vec::new();
    for entry in fs::read_dir(dir).map_err(|e|e.to_string())? {
        let e=entry.map_err(|e|e.to_string())?;
        let name=e.file_name().to_string_lossy().to_string();
        if name.ends_with(".sha256") { continue; }
        names.push(name);
    }
    names.sort();
    if names.is_empty() { return Err("empty bundle dir".into()); }
    let mut data=Vec::new(); let mut files=Vec::new();
    for name in &names {
        let path=dir.join(name);
        let digest=check_sidecar(&path)?;
        let bytes=fs::read(&path).map_err(|e|e.to_string())?;
        files.push((name.clone(),digest,bytes.len()));
        data.extend_from_slice(&bytes);
    }
    let sha=sha_hex(&data);
    Ok(Corpus{data,sha,files})
}

struct Cube { index: usize, data: Vec<u8>, sha: String }

fn partition_cubes(corpus:&[u8])->Vec<Cube> {
    let q=corpus.len()/BASE_COUNT;
    let r=corpus.len()%BASE_COUNT;
    let mut cubes=Vec::new(); let mut start=0usize;
    for i in 0..BASE_COUNT {
        let n=q+usize::from(i<r);
        let end=start+n;
        let data=corpus[start..end].to_vec();
        let sha=sha_hex(&data);
        cubes.push(Cube{index:i+1,data,sha});
        start=end;
    }
    cubes
}

fn cube_coords(i:usize)->(usize,usize,usize) { let k=i-1; (k%3,(k/3)%3,k/9) }

fn axis_order(apex:usize)->Vec<usize> {
    let axis=apex/2; let negative=apex%2==1;
    let mut idx:Vec<usize>=(1..=BASE_COUNT).collect();
    idx.sort_by_key(|&i| {
        let (x,y,z)=cube_coords(i);
        let primary=match axis {0=>x,1=>y,_=>z};
        let p=if negative {2-primary} else {primary};
        (p,x,y,z)
    });
    idx
}

struct BodyInput { index: usize, label: String, composition: String, data: Vec<u8>, sha: String }

fn build_bodies(cubes:&[Cube])->Vec<BodyInput> {
    let mut bodies=Vec::new();
    for c in cubes {
        bodies.push(BodyInput{index:c.index,label:format!("BASE-{:02}",c.index),
            composition:format!("bundle_cube|cube={:02}|bytes={}|timing_free_input=1",c.index,c.data.len()),
            data:c.data.clone(),sha:c.sha.clone()});
    }
    for apex in 0..6 {
        let order=axis_order(apex);
        let mut data=Vec::new(); let mut parts=Vec::new();
        for &i in &order { data.extend_from_slice(&cubes[i-1].data); parts.push(format!("{:02}",i)); }
        let sha=sha_hex(&data);
        bodies.push(BodyInput{index:BASE_COUNT+1+apex,label:format!("APEX{}",APEX_NAMES[apex]),
            composition:format!("bundle_axis_traversal|axis={}|order={}|timing_free_input=1",APEX_NAMES[apex],parts.join(">")),
            data,sha});
    }
    let mut lines=Vec::new();
    lines.push("P3JUNCTIONHDR|schema=PAIS-PATH3-JUNCTION-V1|cubes=27|fields=cube_shas_only|timing_free=1|json=0".to_string());
    for c in cubes { lines.push(format!("P3JUNCTION|cube={:02}|sha256={}|bytes={}|json=0",c.index,c.sha,c.data.len())); }
    let data=(lines.join("\n")+"\n").into_bytes();
    let sha=sha_hex(&data);
    bodies.push(BodyInput{index:BODY_COUNT,label:"OMEGA-JUNCTION".into(),
        composition:"bundle_junction_shas|cubes=27|timing_free=1".into(),data,sha});
    bodies
}

// ---------- body training ----------

struct BodyResult { index: usize, input_sha: String, leaf_sha: String, gain_bytes: u64, accepted: u64, held: u64, codebook_sha: String, lambda: String }

fn checkpoint_body(dir:&Path, input:&BodyInput)->AnyResult<Option<BodyResult>> {
    let meta=dir.join("BODY-META.hbp"); let receipt=dir.join("BODY-RESULT.hbp");
    if !meta.exists()||!receipt.exists(){return Ok(None);}
    let line=fs::read_to_string(&meta).map_err(|e|e.to_string())?; let f=parse_fields(line.trim());
    if f.get("status").map(String::as_str)!=Some("PASS")||f.get("input_sha").map(String::as_str)!=Some(input.sha.as_str()){return Ok(None);}
    if check_sidecar(&receipt).is_err(){return Ok(None);}
    Ok(Some(BodyResult{index:input.index,input_sha:input.sha.clone(),
        leaf_sha:f["leaf_sha"].clone(),
        gain_bytes:f["gain_bytes"].parse().map_err(|_|"ckpt gain")?,
        accepted:f["accepted"].parse().map_err(|_|"ckpt accepted")?,
        held:f["held"].parse().map_err(|_|"ckpt held")?,
        codebook_sha:f["codebook_sha"].clone(),
        lambda:f["lambda"].clone()}))
}

fn train_body(input:&BodyInput, out_root:&Path, contract_sha:&str, bundle_sha:&str, seat_pid:&str)->AnyResult<BodyResult> {
    let body_dir=out_root.join(format!("body-{:02}",input.index));
    fs::create_dir_all(&body_dir).map_err(|e|e.to_string())?;
    if let Some(r)=checkpoint_body(&body_dir,input)?{println!("BODY_RESUME|body={:02}|status=PASS",input.index);return Ok(r);}
    let started=Instant::now();
    let source_sha=sha256(&input.data);
    let raw_glyphs=bytes_to_glyphs(&input.data,BITS);
    let (perm,inv,codebook_sha)=language_codebook(&source_sha,BITS);
    let glyphs=speak(&raw_glyphs,&perm);
    let heard:Vec<u16>=glyphs.iter().map(|&g| inv[g as usize]).collect();
    if heard!=raw_glyphs||glyphs_to_bytes(&heard,BITS,input.data.len())!=input.data {return Err(format!("body {:02} language roundtrip failed",input.index));}
    println!("BODY_START|body={:02}|label={}|bytes={}|glyphs={}|codebook={}",input.index,input.label,input.data.len(),glyphs.len(),&codebook_sha[..16]);
    let native_sha=sha256(&pack_glyphs(&glyphs,BITS));
    let (group_ok,vertex_hashes,group_detail)=group_gate_glyphs(&glyphs,BITS);
    if !group_ok{return Err(format!("body {:02} glyph R/N/Q group gate failed: {}",input.index,group_detail));}
    let mut rows=Vec::new();
    rows.push(format!("PATH3BODYHDR|schema=PAIS-PATH3-LEVEL2-BODY-V1|body={:02}|bits=10|label={}|input_bytes={}|input_glyphs={}|input_sha256={}|contract_sha256={}|bundle_sha256={}|cells=800|content_free=hashes_and_counts_only|higher_floors=HELD|json=0",input.index,input.label,input.data.len(),glyphs.len(),input.sha,contract_sha,bundle_sha));
    rows.push(format!("COMPOSE|body={:02}|{}|json=0",input.index,input.composition));
    rows.push(format!("LANGUAGE|body={:02}|law=LANGUAGE_GENESIS_V1|codebook_sha256={}|alphabet=1024|seeded_by=body_sha256|never_english=1|translation=receipted_permutation|roundtrip=1|prediction=gains_equal_up_to_tie_break_by_bijection_invariance|json=0",input.index,codebook_sha));
    rows.push(format!("GROUPGATE|body={:02}|group=C2^3_CONFIRMED_ON_NATIVE_GLYPHS|{}|vertices_sha256={}|status=PASS|json=0",input.index,group_detail,sha_hex(vertex_hashes.join("|").as_bytes())));
    let mut play_rows=Vec::new();
    for (axis,name) in [("R","R"),("N","N"),("Q","Q")] {
        let moved=match name {"R"=>g_r(&glyphs),"N"=>g_n(&glyphs,BITS),_=>g_q(&glyphs,BITS)};
        let back=match name {"R"=>g_r(&moved),"N"=>g_n(&moved,BITS),_=>g_q(&moved,BITS)};
        if back!=glyphs{return Err(format!("body {:02} axis {} failed",input.index,axis));}
        for sign in ['+','-'] {play_rows.push(format!("PLAY|body={:02}|dir={}{}|axis={}|from_sha256={}|to_sha256={}|roundtrip=1|same_transform_for_sign=1|json=0",input.index,sign,name,axis,input.sha,sha_hex(&pack_glyphs(&moved,BITS))));}
    }
    let play_gate_sha=sha_hex((play_rows.join("\n")+"\n").as_bytes()); rows.extend(play_rows);
    let mut gain_total=0u64; let mut accepted=0u64; let mut held=0u64; let mut best_payload=usize::MAX;
    for a in 0..8 {
        let view=a_apply_glyphs(a,&glyphs,BITS,&native_sha);
        let restored=a_inverse_glyphs(a,&view,BITS,&native_sha);
        if restored!=glyphs{return Err(format!("body {:02} A inverse {} failed",input.index,A_NAMES[a]));}
        let view_packed=pack_glyphs(&view,BITS);
        let view_sha=sha_hex(&view_packed);
        rows.push(format!("AVIEWGATE|body={:02}|a={}|view_sha256={}|roundtrip=1|json=0",input.index,A_NAMES[a],view_sha));
        for direction in 0..2u8 { for order in 1..=5u8 {
            let seq:Vec<u16>=if direction==0{view.clone()}else{view.iter().rev().copied().collect()};
            let mut enc=PredictorModel::new(BITS,order,direction);
            let mut dec=PredictorModel::new(BITS,order,direction);
            for epoch in 1..=EPOCHS {
                let before=hex(&enc.commit);
                let (residual,m)=enc.encode(&seq);
                let payload=lz_compress(&pack_glyphs(&residual,BITS));
                let payload_sha=sha_hex(&payload);
                let decoded_packed=lz_decompress(&payload)?;
                let decoded_residual=unpack_glyphs(&decoded_packed,BITS,seq.len());
                let (decoded_seq,dm)=dec.decode(&decoded_residual);
                let state_match=enc.commit==dec.commit&&enc.counts.len()==dec.counts.len()&&enc.best.len()==dec.best.len()&&m.predictions==dm.predictions&&m.unseen_contexts==dm.unseen_contexts;
                if decoded_seq!=seq||!state_match{return Err(format!("body {:02} cell restore a={} d={} o={} e={}",input.index,a,direction,order,epoch));}
                if epoch==EPOCHS&&enc!=dec{return Err(format!("body {:02} terminal model mismatch a={} d={} o={}",input.index,a,direction,order));}
                let cost=payload.len();
                let gain=view_packed.len().saturating_sub(cost) as u64;
                let decision=if gain>0{accepted+=1;gain_total+=gain;"ACCEPT"}else{held+=1;"HOLD"};
                best_payload=best_payload.min(cost);
                let actor=pid8(&format!("PAIS-P3|{:02}|{}|{}|{}",input.index,A_NAMES[a],B_DIRECTIONS[direction as usize],order));
                rows.push(format!("CELL|body={:02}|a={}|b_direction={}|b_order={}|c_epoch={}|actor_pid={}|input_sha256={}|view_sha256={}|state_before={}|state_after={}|predictions={}|top1_correct={}|unseen_contexts={}|novel_pairs={}|confident_blunders={}|model_pairs={}|payload_bytes={}|payload_sha256={}|gain_bytes={}|decision={}|restore=1|state_match=1|play_gate_sha256={}|conditioning=VARIABLE_ORDER_PREDICTIVE_RESIDUAL_GLYPH_V2|json=0",input.index,A_NAMES[a],B_DIRECTIONS[direction as usize],order,epoch,actor,input.sha,view_sha,before,hex(&enc.commit),m.predictions,m.top1_correct,m.unseen_contexts,m.novel_pairs,m.confident_blunders,enc.counts.len(),cost,payload_sha,gain,decision,play_gate_sha));
            }
        }}
    }
    if accepted+held!=800{return Err(format!("body {:02} cell count {}",input.index,accepted+held));}
    rows.push(format!("DENSITY|scope=body|body={:02}|ledger=BUNDLE_GLYPHS|accepted_gain_bytes={}|input_glyphs={}|accepted={}|held={}|meaning=structure_repetition_only|archive_ratio=NOT_CLAIMED|json=0",input.index,gain_total,glyphs.len(),accepted,held));
    rows.push(format!("BODYRESTORE|body={:02}|input_sha256={}|restore=1|leaf_preimage=timing_free|json=0",input.index,input.sha));
    let leaf_sha=sha_hex((rows.join("\n")+"\n").as_bytes());
    rows.push(format!("OMEGALEAF|body={:02}|input_sha256={}|cells=800|leaf_sha256={}|restore=1|json=0",input.index,input.sha,leaf_sha));
    rows.push(format!("TIMING|body={:02}|elapsed_ms={}|hashed_into_leaf=0|json=0",input.index,started.elapsed().as_millis()));
    let body_pid=pid8(&format!("PATH3-BODY|{}",input.sha));
    let (x,y,z)=if input.index<=BASE_COUNT {cube_coords(input.index)} else {(9,9,9)};
    let manifold=format!("cube3:{},{},{}",x,y,z);
    let seq=format!("{}",input.index);
    let fields:[(&str,&str);19]=[
        ("actor",seat_pid),("verb","TRAIN_LEVEL2"),("target",&body_pid),("layer","PATH3_BRIDGE_FLOOR2"),
        ("gate","800_CELLS_STATE_MATCH"),("state","SEALED"),("chain",bundle_sha),("pid",&body_pid),
        ("time",&seq),("omni_direction","omni_submit"),("provenance","ACER_LOCAL_SILICON"),
        ("mirror","CONTENT_FREE_GITHUB"),("hyperlanguage",&codebook_sha),("encryption","NONE"),
        ("audit",&leaf_sha),("quorum","SEAT_SINGLE"),("manifold",&manifold),("signature",&leaf_sha),
        ("omega_state","closure"),
    ];
    let lambda=omnisubmit_leaf(&fields);
    rows.push(format!("OMNISUBMIT|body={:02}|schema=PATH3-LEAF-V1|actor={}|verb=TRAIN_LEVEL2|pid={}|time_seq={}|omni_direction=omni_submit|hyperlanguage={}|manifold={}|omega_state=closure|lambda={}|wall_clock_in_leaf=0|json=0",input.index,seat_pid,body_pid,seq,&codebook_sha[..16],manifold,lambda));
    rows.push(format!("PATH3BODYFTR|body={:02}|cells=800|accepted={}|held={}|gain_bytes={}|best_payload_bytes={}|restore=1|status=PASS|json=0",input.index,accepted,held,gain_total,best_payload));
    let receipt=body_dir.join("BODY-RESULT.hbp");
    write_lf(&receipt,&(rows.join("\n")+"\n"))?; write_sidecar(&receipt)?;
    let meta=body_dir.join("BODY-META.hbp");
    write_lf(&meta,&format!("P3BODYMETA|body={:02}|input_sha={}|leaf_sha={}|gain_bytes={}|accepted={}|held={}|codebook_sha={}|lambda={}|status=PASS|json=0\n",input.index,input.sha,leaf_sha,gain_total,accepted,held,codebook_sha,lambda))?;
    write_sidecar(&meta)?;
    println!("BODY_OK|body={:02}|cells=800|accepted={}|held={}|gain={}|lambda={}",input.index,accepted,held,gain_total,&lambda[..16]);
    Ok(BodyResult{index:input.index,input_sha:input.sha.clone(),leaf_sha,gain_bytes:gain_total,accepted,held,codebook_sha,lambda})
}

fn hbi_for(hbp:&str)->String {
    let mut out=String::new();
    for (i,line) in hbp.lines().enumerate(){out.push_str(&format!("HBI|row={}|sha256={}|hex={}|json=0\n",i+1,sha_hex(line.as_bytes()),hex(line.as_bytes())));} out
}

fn run_train(bundle:&Path, contract:&Path, output:&Path, workers:usize, seat_pid:&str)->AnyResult<()> {
    fs::create_dir_all(output).map_err(|e|e.to_string())?;
    let contract_bytes=fs::read(contract).map_err(|e|e.to_string())?;
    let contract_sha=sha_hex(&contract_bytes);
    let corpus=load_bundle(bundle)?;
    println!("BUNDLE_OK|files={}|bytes={}|sha256={}",corpus.files.len(),corpus.data.len(),corpus.sha);
    let cubes=partition_cubes(&corpus.data);
    let restored:Vec<u8>=cubes.iter().flat_map(|c|c.data.iter().copied()).collect();
    if restored!=corpus.data {return Err("cube concatenation restore failed".into());}
    let zero=vec![0u16;4096];
    let (zero_pass,_,_)=group_gate_glyphs(&zero,BITS);
    if zero_pass{return Err("zero glyph distinctness negative control failed".into());}
    let mut corrupt=corpus.data.clone(); if let Some(first)=corrupt.first_mut(){*first^=1;}
    if sha_hex(&corrupt)==corpus.sha {return Err("corruption negative control failed".into());}
    let bodies=build_bodies(&cubes);
    let mut cb=HashSet::new();
    for b in &bodies { let (_,_,c)=language_codebook(&sha256(&b.data),BITS); if !cb.insert(c) {return Err("duplicate native language codebook".into());} }
    let queue=Arc::new(Mutex::new(VecDeque::from(bodies.iter().map(|b|b.index).collect::<Vec<_>>())));
    let bodies_arc=Arc::new(bodies);
    let (tx,rx)=mpsc::channel();
    let worker_count=workers.max(1).min(BODY_COUNT);
    let out_arc=Arc::new(output.to_path_buf());
    let cs=Arc::new(contract_sha.clone());
    let bs=Arc::new(corpus.sha.clone());
    let sp=Arc::new(seat_pid.to_string());
    let mut handles=Vec::new();
    for _ in 0..worker_count{
        let q=Arc::clone(&queue); let tx=tx.clone(); let out=Arc::clone(&out_arc);
        let cs=Arc::clone(&cs); let bs=Arc::clone(&bs); let sp=Arc::clone(&sp); let ins=Arc::clone(&bodies_arc);
        handles.push(thread::spawn(move||loop{
            let body={q.lock().unwrap().pop_front()};
            match body{Some(b)=>{let input=&ins[b-1];let r=train_body(input,&out,&cs,&bs,&sp);let _=tx.send(r);},None=>break}
        }));
    }
    drop(tx);
    let mut results=Vec::new(); let mut errors=Vec::new();
    for r in rx{match r{Ok(x)=>results.push(x),Err(e)=>errors.push(e)}}
    for h in handles{let _=h.join();}
    if !errors.is_empty(){return Err(errors.join("; "));}
    if results.len()!=BODY_COUNT{return Err(format!("expected {} body results got {}",BODY_COUNT,results.len()));}
    results.sort_by_key(|r|r.index);
    let mut hbp=Vec::new();
    hbp.push(format!("PATH3FLOORHDR|schema=PAIS-PATH3-LEVEL2-V1|authority=OPERATOR_BUILD_MISSING_PARTS_2026-07-16|mode=SHADOW_MEASURED|floor=2_bridge|body_count=34|base=27|apex=6|junction=1|bits=10|languages=34_distinct_native|ring_a=8|ring_b=10|ring_c=10|cells_per_body=800|cells_total=27200|contract_sha256={}|bundle_sha256={}|publication=CONTENT_FREE_RECEIPTS_ONLY|higher_floors=HELD|json=0",contract_sha,corpus.sha));
    for (name,digest,len) in &corpus.files {
        hbp.push(format!("BUNDLEFILE|name={}|sha256={}|bytes={}|json=0",name,digest,len));
    }
    hbp.push("CONTROL|name=ALL_ZERO_GLYPH_DISTINCTNESS|expected=FAIL_DISTINCT|observed=FAIL_DISTINCT|status=PASS|json=0".into());
    hbp.push("CONTROL|name=ONE_BYTE_CORRUPTION|expected=SHA_DIFFERENT|observed=SHA_DIFFERENT|status=PASS|json=0".into());
    hbp.push("CONTROL|name=34_DISTINCT_NATIVE_LANGUAGES|expected=ALL_DISTINCT|observed=ALL_DISTINCT|status=PASS|json=0".into());
    let mut total_gain=0u64; let mut total_accept=0u64; let mut total_hold=0u64;
    let mut leaves=Vec::new(); let mut lambdas=Vec::new();
    for r in &results{
        let receipt=output.join(format!("body-{:02}",r.index)).join("BODY-RESULT.hbp");
        let text=fs::read_to_string(&receipt).map_err(|e|e.to_string())?;
        hbp.extend(text.lines().map(str::to_string));
        total_gain+=r.gain_bytes; total_accept+=r.accepted; total_hold+=r.held;
        leaves.push(format!("OMEGALEAFREF|body={:02}|input_sha256={}|leaf_sha256={}|codebook_sha256={}|lambda={}|json=0",r.index,r.input_sha,r.leaf_sha,r.codebook_sha,r.lambda));
        lambdas.push(r.lambda.clone());
    }
    let anchor=format!("OMEGAANCHOR|schema=PAIS-PATH3-LEVEL2-V1|contract_sha256={}|bundle_sha256={}|body_count=34|epoch=1|json=0",contract_sha,corpus.sha);
    let omega=sha_hex((anchor.clone()+"\n"+&leaves.join("\n")+"\n").as_bytes());
    let epoch_root=omnisubmit_epoch_root(1,&corpus.sha,&lambdas);
    hbp.push(anchor); hbp.extend(leaves);
    hbp.push(format!("OMEGACENTER|method=sha256_over_anchor_plus_34_ordered_leaves_lf|omega_sha256={}|leaf_count=34|json=0",omega));
    hbp.push(format!("OMNIROOT|schema=PATH3-OMEGA-V1|epoch=1|parent=bundle_sha256|epoch_root={}|lambda_count=34|law=H(D_Omega||e||Omega_prev||sorted_lambdas)|domain_separated=1|length_prefixed=1|json=0",epoch_root));
    let total_glyphs:u64=results.iter().map(|r|{let b=&bodies_arc[r.index-1].data;((b.len() as u64)*8+9)/10}).sum();
    hbp.push(format!("DENSITY|scope=cohort|ledger=BUNDLE_GLYPHS|accepted_gain_bytes={}|input_glyphs={}|accepted={}|held={}|meaning=structure_repetition_only|archive_ratio=NOT_CLAIMED|json=0",total_gain,total_glyphs,total_accept,total_hold));
    hbp.push(format!("PATH3FLOORFTR|cells=27200|accepted={}|held={}|restore_bodies=34_of_34|languages=34_distinct|omega={}|omni_epoch_root={}|higher_floors=HELD|compression_record=NOT_CLAIMED|status=PASS|json=0",total_accept,total_hold,omega,epoch_root));
    let floor_text=hbp.join("\n")+"\n";
    let floor=output.join("PAIS-PATH3-LEVEL2-RESULT.hbp");
    write_lf(&floor,&floor_text)?;
    let floor_sha=write_sidecar(&floor)?;
    let hbi=output.join("PAIS-PATH3-LEVEL2-RESULT.hbi");
    write_lf(&hbi,&hbi_for(&floor_text))?;
    let hbi_sha=write_sidecar(&hbi)?;
    let sums=format!("{}  PAIS-PATH3-LEVEL2-RESULT.hbp\n{}  PAIS-PATH3-LEVEL2-RESULT.hbi\n",floor_sha,hbi_sha);
    let sums_path=output.join("SHA256SUMS");
    write_lf(&sums_path,&sums)?; write_sidecar(&sums_path)?;
    println!("PATH3_LEVEL2_PASS|bodies=34|cells=27200|accepted={}|held={}|gain_bytes={}|languages=34_distinct|omega={}|omni_epoch_root={}|result_sha256={}|content_free=1|higher_floors=HELD",total_accept,total_hold,total_gain,omega,epoch_root,floor_sha);
    Ok(())
}

// ---------- selftest ----------

fn selftest()->AnyResult<()> {
    let mut data=Vec::new(); let mut seed=sha256(b"PATH3-SELFTEST-V1");
    while data.len()<50000 { data.extend_from_slice(&seed); seed=sha256(&seed); }
    data.truncate(49999);
    let src=sha256(&data);
    let (perm,inv,cb1)=language_codebook(&src,BITS);
    let mut sorted=perm.clone(); sorted.sort();
    if sorted!=(0..1024u16).collect::<Vec<_>>() {return Err("codebook not a permutation".into());}
    let raw=bytes_to_glyphs(&data,BITS);
    let native=speak(&raw,&perm);
    let heard:Vec<u16>=native.iter().map(|&g| inv[g as usize]).collect();
    if heard!=raw||glyphs_to_bytes(&heard,BITS,data.len())!=data {return Err("language roundtrip".into());}
    let other=sha256(b"OTHER-BODY");
    let (_,_,cb2)=language_codebook(&other,BITS);
    if cb1==cb2 {return Err("two bodies share a language".into());}
    let (ok,_,detail)=group_gate_glyphs(&native,BITS);
    if !ok {return Err(format!("group gate on native glyphs: {}",detail));}
    let nsha=sha256(&pack_glyphs(&native,BITS));
    for a in 0..8 {
        let v=a_apply_glyphs(a,&native,BITS,&nsha);
        if a_inverse_glyphs(a,&v,BITS,&nsha)!=native {return Err(format!("A{} inverse",a));}
    }
    let f1:[(&str,&str);2]=[("actor","x"),("verb","y")];
    let f2:[(&str,&str);2]=[("actor","xy"),("verb","")];
    if omnisubmit_leaf(&f1)==omnisubmit_leaf(&f2) {return Err("length prefixing failed: ambiguous concatenation".into());}
    let l1=vec!["bb".to_string(),"aa".to_string()];
    let l2=vec!["aa".to_string(),"bb".to_string()];
    if omnisubmit_epoch_root(1,"p",&l1)!=omnisubmit_epoch_root(1,"p",&l2) {return Err("epoch root not order-independent".into());}
    if omnisubmit_epoch_root(1,"p",&l1)==omnisubmit_epoch_root(2,"p",&l1) {return Err("epoch root ignores epoch".into());}
    println!("SELFTEST_PASS|codebook=permutation_distinct_reversible|group=OK|lanes=8|omnisubmit=domain_separated_length_prefixed_sorted");
    Ok(())
}

fn flag(args:&[String],name:&str)->AnyResult<String>{let i=args.iter().position(|x|x==name).ok_or_else(||format!("missing {}",name))?;args.get(i+1).cloned().ok_or_else(||format!("missing value for {}",name))}

fn main()->Result<(),String>{
    let args:Vec<String>=env::args().collect();
    if args.len()<2{return Err("usage: selftest | train --bundle DIR --contract PATH --output DIR [--workers N] [--seat PID]".into());}
    match args[1].as_str() {
        "selftest"=>selftest(),
        "train"=>{
            let bundle=PathBuf::from(flag(&args,"--bundle")?);
            let contract=PathBuf::from(flag(&args,"--contract")?);
            let output=PathBuf::from(flag(&args,"--output")?);
            let workers=flag(&args,"--workers").ok().and_then(|x|x.parse().ok()).unwrap_or(4);
            let seat=flag(&args,"--seat").unwrap_or_else(|_|"8467a937cba309f7".into());
            run_train(&bundle,&contract,&output,workers,&seat)
        },
        _=>Err("unknown command".into()),
    }
}
