// Interactive evidence-bundle check. A from-scratch verifier that runs entirely in your browser:
// its own canonicalizer, its own SHA-256/512, and a hand-rolled RFC 8032 Ed25519 -- no libraries, no
// network, no Web Crypto dependency (so it runs in any context, sandbox or file://), and no SMRFORGE
// code. A passing verify here is not the producer marking its own homework. Ported 1:1 from
// smrf_verify/verify.py.
import { BUNDLE_TEXT } from './check-bundle.js';

// SMRFORGE's pinned signing public key. It still equals the public DEMO identity, so a passing verify
// proves INTEGRITY (the bundle was not edited), not ORIGIN (that it came from SMRFORGE). This flips
// itself the day a real production key is generated out-of-repo and the bundles re-signed.
const PINNED_PUBKEY = '069aba87747dd9c1f46f24004eb79e05eb8f2e0f2c3adfdde60c1e2e00bac838';
const DEMO_PUBKEY   = '069aba87747dd9c1f46f24004eb79e05eb8f2e0f2c3adfdde60c1e2e00bac838';
const PINNED_IS_DEMO = PINNED_PUBKEY === DEMO_PUBKEY;

// ---------- raw-literal-preserving JSON parse (JSON.parse would collapse 30.0 -> 30) ----------
class NumLit { constructor(raw) { this.raw = raw; } }
function parseJSON(text) {
  let i = 0;
  const ws = () => { while (i < text.length && ' \t\n\r'.includes(text[i])) i++; };
  function val() {
    ws();
    const c = text[i];
    if (c === '{') return obj();
    if (c === '[') return arr();
    if (c === '"') return str();
    if (c === 't') { i += 4; return true; }
    if (c === 'f') { i += 5; return false; }
    if (c === 'n') { i += 4; return null; }
    return num();
  }
  function obj() { const o = {}; i++; ws(); if (text[i] === '}') { i++; return o; } for (;;) { ws(); const k = str(); ws(); i++; o[k] = val(); ws(); if (text[i] === ',') { i++; continue; } i++; return o; } }
  function arr() { const a = []; i++; ws(); if (text[i] === ']') { i++; return a; } for (;;) { a.push(val()); ws(); if (text[i] === ',') { i++; continue; } i++; return a; } }
  function str() { i++; let s = ''; for (;;) { const c = text[i++]; if (c === '"') return s; if (c === '\\') { const e = text[i++]; if (e === 'u') { s += String.fromCharCode(parseInt(text.slice(i, i + 4), 16)); i += 4; } else s += { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }[e]; } else s += c; } }
  function num() { const m = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(i)); i += m[0].length; return new NumLit(m[0]); }
  return val();
}

// ---------- Python-compatible canon: json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True) ----------
function pyStr(s) {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\b') out += '\\b';
    else if (ch === '\f') out += '\\f';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (cp < 0x20 || cp > 0x7e) {
      if (cp > 0xffff) { const h = cp - 0x10000; out += '\\u' + (0xd800 + (h >> 10)).toString(16).padStart(4, '0') + '\\u' + (0xdc00 + (h & 0x3ff)).toString(16).padStart(4, '0'); }
      else out += '\\u' + cp.toString(16).padStart(4, '0');
    } else out += ch;
  }
  return out + '"';
}
function canon(v) {
  if (v instanceof NumLit) return v.raw;
  if (typeof v === 'string') return pyStr(v);
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (v === null) return 'null';
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  const keys = Object.keys(v).sort();
  return '{' + keys.map(k => pyStr(k) + ':' + canon(v[k])).join(',') + '}';
}
const _enc = new TextEncoder();

// ---------- SHA-256 (pure JS, no Web Crypto) ----------
const _K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
function sha256hex(msg) {
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a, h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const l = msg.length, total = (((l + 8) >> 6) + 1) * 64, m = new Uint8Array(total);
  m.set(msg); m[l] = 0x80;
  const dv = new DataView(m.buffer);
  dv.setUint32(total - 8, Math.floor(l / 0x20000000)); dv.setUint32(total - 4, (l * 8) >>> 0);
  const w = new Uint32Array(64), rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let i = 0; i < total; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) { const a = w[t - 15], b = w[t - 2]; const s0 = (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) >>> 0; const s1 = (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10)) >>> 0; w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0; }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), ch = (e & f) ^ (~e & g), t1 = (hh + S1 + ch + _K256[t] + w[t]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
  }
  const hex = (x) => ('0000000' + (x >>> 0).toString(16)).slice(-8);
  return hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h5) + hex(h6) + hex(h7);
}
const sha = (str) => 'sha256:' + sha256hex(_enc.encode(str));

// ---------- SHA-512 (pure JS, BigInt 64-bit) -> Uint8Array(64) ----------
const _MASK64 = (1n << 64n) - 1n;
const _K512 = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn, 0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n, 0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n, 0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
  0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n, 0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
  0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn, 0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
  0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n, 0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n, 0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn, 0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
  0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n, 0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
  0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn, 0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n];
function sha512(msg) {
  let H = [0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n, 0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n];
  const l = msg.length, total = (((l + 16) >> 7) + 1) * 128, m = new Uint8Array(total);
  m.set(msg); m[l] = 0x80;
  const bitLen = BigInt(l) * 8n;
  for (let j = 0; j < 8; j++) m[total - 1 - j] = Number((bitLen >> BigInt(8 * j)) & 0xffn);
  const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & _MASK64;
  const w = new Array(80);
  for (let i = 0; i < total; i += 128) {
    for (let t = 0; t < 16; t++) { let v = 0n; for (let b = 0; b < 8; b++) v = (v << 8n) | BigInt(m[i + t * 8 + b]); w[t] = v; }
    for (let t = 16; t < 80; t++) { const a = w[t - 15], b = w[t - 2]; const s0 = rotr(a, 1n) ^ rotr(a, 8n) ^ (a >> 7n); const s1 = rotr(b, 19n) ^ rotr(b, 61n) ^ (b >> 6n); w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & _MASK64; }
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 80; t++) {
      const S1 = rotr(e, 14n) ^ rotr(e, 18n) ^ rotr(e, 41n), ch = (e & f) ^ ((~e & _MASK64) & g), t1 = (h + S1 + ch + _K512[t] + w[t]) & _MASK64;
      const S0 = rotr(a, 28n) ^ rotr(a, 34n) ^ rotr(a, 39n), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) & _MASK64;
      h = g; g = f; f = e; e = (d + t1) & _MASK64; d = c; c = b; b = a; a = (t1 + t2) & _MASK64;
    }
    H = [(H[0] + a) & _MASK64, (H[1] + b) & _MASK64, (H[2] + c) & _MASK64, (H[3] + d) & _MASK64, (H[4] + e) & _MASK64, (H[5] + f) & _MASK64, (H[6] + g) & _MASK64, (H[7] + h) & _MASK64];
  }
  const out = new Uint8Array(64);
  for (let j = 0; j < 8; j++) for (let b = 0; b < 8; b++) out[j * 8 + b] = Number((H[j] >> BigInt(56 - 8 * b)) & 0xffn);
  return out;
}

// ---------- from-scratch RFC 8032 Ed25519 verify (BigInt field arithmetic) ----------
const Q = (2n ** 255n) - 19n;
const mod = (a) => ((a % Q) + Q) % Q;
function modpow(b, e, mm) { b = ((b % mm) + mm) % mm; let r = 1n; while (e > 0n) { if (e & 1n) r = r * b % mm; b = b * b % mm; e >>= 1n; } return r; }
const inv = (a) => modpow(mod(a), Q - 2n, Q);
const D = mod(-121665n * inv(121666n));
const ISQRT = modpow(2n, (Q - 1n) / 4n, Q);
function recoverX(y, sign) { const yy = y * y; const xx = mod((yy - 1n) * inv(D * yy + 1n)); let x = modpow(xx, (Q + 3n) / 8n, Q); if (mod(x * x - xx) !== 0n) x = mod(x * ISQRT); if ((x & 1n) !== BigInt(sign)) x = Q - x; return x; }
const BY = mod(4n * inv(5n));
const BASE = [recoverX(BY, 0), BY];
function add(p, q) { const [x1, y1] = p, [x2, y2] = q; const t = D * x1 * x2 * y1 * y2; const x3 = mod((x1 * y2 + x2 * y1) * inv(1n + t)); const y3 = mod((y1 * y2 + x1 * x2) * inv(1n - t)); return [x3, y3]; }
function mul(p, e) { let r = [0n, 1n]; while (e > 0n) { if (e & 1n) r = add(r, p); p = add(p, p); e >>= 1n; } return r; }
const onCurve = (p) => { const [x, y] = p; return mod(-x * x + y * y - 1n - D * x * x * y * y) === 0n; };
const leInt = (b) => { let n = 0n; for (let j = b.length - 1; j >= 0; j--) n = (n << 8n) | BigInt(b[j]); return n; };
function decodepoint(b) { const y = leInt(b) & ((1n << 255n) - 1n); const x = recoverX(y, (b[31] >> 7) & 1); const p = [x, y]; if (!onCurve(p)) throw new Error('off curve'); return p; }
const hexToBytes = (h) => { const a = new Uint8Array(h.length / 2); for (let j = 0; j < a.length; j++) a[j] = parseInt(h.substr(j * 2, 2), 16); return a; };
function ed25519Verify(sig, msgStr, pub) {
  if (sig.length !== 64 || pub.length !== 32) return false;
  let r, a;
  try { r = decodepoint(sig.slice(0, 32)); a = decodepoint(pub); } catch { return false; }
  const s = leInt(sig.slice(32));
  const msg = _enc.encode(msgStr);
  const buf = new Uint8Array(64 + msg.length);
  buf.set(sig.slice(0, 32), 0); buf.set(pub, 32); buf.set(msg, 64);
  const k = leInt(sha512(buf));
  const L = mul(BASE, s), Rk = add(r, mul(a, k));
  return L[0] === Rk[0] && L[1] === Rk[1];
}

// ---------- verify_bundle: returns a structured checklist so the UI can show each step ----------
function verifyBundle(bundle) {
  const checks = [];
  const add_ = (name, ok, detail) => checks.push({ name, ok, detail });

  add_('Envelope schema recognised', bundle.schema === 'smrforge.evidence_envelope.v1', bundle.schema);

  const manifest = bundle.manifest || {}, sums = bundle.sha256sums || {};
  for (const side of ['inputs', 'result', 'provenance']) {
    const blk = manifest[side] || {};
    const rc = sha(canon(blk.value));
    const ok = blk.sha256 === sums[side] && rc === blk.sha256;
    add_(`${side} section matches its sealed fingerprint`, ok, ok ? blk.sha256 : `recomputed ${rc} ≠ sealed ${sums[side]}`);
  }
  add_('Readable result equals the hashed result', canon(bundle.result) === canon(manifest.result?.value));
  add_('Readable provenance equals the hashed provenance', canon(bundle.reproducibility) === canon(manifest.provenance?.value));

  const rb = sha(canon(sums));
  const sealOk = rb === bundle.bundle_sha256;
  add_('Bundle seal covers the whole fingerprint list', sealOk, sealOk ? rb : `recomputed ${rb} ≠ ${bundle.bundle_sha256}`);

  const sig = bundle.signature;
  let sigOk = false, sigDetail = '';
  if (!sig || sig.alg !== 'ed25519') sigDetail = 'no ed25519 signature';
  else if (sig.public_key !== PINNED_PUBKEY) sigDetail = 'not under the pinned key';
  else { sigOk = ed25519Verify(hexToBytes(sig.signature), rb, hexToBytes(PINNED_PUBKEY)); sigDetail = sigOk ? 'valid' : 'does not verify'; }
  add_('Ed25519 signature over the seal is valid', sigOk, sigDetail);

  return { ok: checks.every(c => c.ok), checks };
}

// expose the pure core for a headless (Node) parity test
export { BUNDLE_TEXT, parseJSON, canon, verifyBundle, NumLit, PINNED_IS_DEMO, sha256hex, sha512 };

// ======================================================================================
// UI wiring -- runs only in a browser; a Node import of the functions above skips all of this
// ======================================================================================
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initUI);
  else initUI();
}

const trunc = (h, n = 10) => { const s = String(h).replace('sha256:', ''); return 'sha256:' + s.slice(0, n) + '…' + s.slice(-6); };

function initUI() {
  const bundle = parseJSON(BUNDLE_TEXT);
  // the two live-editable nodes for guided tamper (both readable + hashed copies, so an edit reads
  // like a real doctored file): k_eff, and the nuclear-data pin
  const kNodes = [
    bundle.result.result['physics:openmc'].k_eff,
    bundle.manifest.result.value.result['physics:openmc'].k_eff,
  ];
  const K0 = kNodes[0].raw;
  const DL0 = bundle.reproducibility.data_library_sha256;

  renderStatic(bundle);

  const kInput = document.getElementById('tamper-k');
  const dlInput = document.getElementById('tamper-dl');
  kInput.value = K0;
  dlInput.value = DL0;

  function run() {
    kNodes.forEach(n => { n.raw = kInput.value.trim() === '' ? '0' : kInput.value.trim(); });
    bundle.reproducibility.data_library_sha256 = dlInput.value;
    bundle.manifest.provenance.value.data_library_sha256 = dlInput.value;
    const tampered = kInput.value.trim() !== K0 || dlInput.value !== DL0;
    const { ok, checks } = verifyBundle(bundle);
    renderVerdict(ok, checks, tampered);
  }

  // verify is real crypto, not free -- debounce so fast typing doesn't run one per keystroke
  let deb;
  const runSoon = () => { clearTimeout(deb); deb = setTimeout(run, 90); };
  document.getElementById('btn-verify').addEventListener('click', run);
  kInput.addEventListener('input', runSoon);
  dlInput.addEventListener('input', runSoon);
  document.getElementById('btn-reset').addEventListener('click', () => { kInput.value = K0; dlInput.value = DL0; run(); });

  // console self-test so a real-browser regression is visible
  try {
    const fresh = parseJSON(BUNDLE_TEXT);
    const clean = verifyBundle(fresh);
    fresh.result.result['physics:openmc'].k_eff.raw = '1.5';
    const dirty = verifyBundle(fresh);
    console.info(`[check self-test] real=${clean.ok ? 'PASS' : 'FAIL'}  tampered=${dirty.ok ? 'PASS(!)' : 'caught'}`);
  } catch (e) { console.error('[check self-test] error', e); }

  run();
}

function renderStatic(bundle) {
  const core = bundle.result;
  const rep = bundle.reproducibility;
  const k = bundle.result.result['physics:openmc'].k_eff.raw;
  const ks = bundle.result.result['physics:openmc'].k_eff_sigma.raw;
  const el = (id) => document.getElementById(id);
  el('claim-k').textContent = k;
  el('claim-sigma').textContent = ks;
  el('claim-fidelity').textContent = core.fidelity;
  el('claim-verdict').textContent = core.verdict;

  el('prov-rows').innerHTML = [
    ['engine', bundle.result.result['physics:openmc'].engine],
    ['engine_version', rep.engine_version],
    ['code_version', rep.code_version],
    ['data_library', rep.data_library],
    ['data_library_sha256', trunc(rep.data_library_sha256)],
    ['rng_seed', rep.rng_seed.raw],
  ].map(([k2, v]) => `<div class="hr-row"><span class="hr-k">${k2}</span><span class="hr-v">${v}</span></div>`).join('');

  el('seal-rows').innerHTML = ['inputs', 'result', 'provenance']
    .map(s => `<div class="hr-row"><span class="hr-k">${s}</span><span class="hr-hash">${trunc(bundle.sha256sums[s])}</span></div>`).join('');
  el('sig-key').textContent = trunc('sha256:' + bundle.signature.public_key).replace('sha256:', '');
  el('bundle-seal').textContent = trunc(bundle.bundle_sha256);

  const kf = parseFloat(k), sf = parseFloat(ks), lo = kf - 3 * sf, hi = kf + 3 * sf;
  el('band-lo').textContent = lo.toFixed(5);
  el('band-hi').textContent = hi.toFixed(5);
  el('band-center-mark').setAttribute('data-label', `${k} ± ${ks}`);
}

function renderVerdict(ok, checks, tampered) {
  const banner = document.getElementById('verdict-banner');
  banner.className = 'verdict-banner ' + (ok ? 'is-pass' : 'is-fail');
  banner.innerHTML = ok
    ? `<span class="v-mark">✓</span> VERIFIED — this bundle is intact and unedited. The check just ran in your browser.`
    : `<span class="v-mark">✗</span> BROKEN — you changed the record, and the seal caught it.`;

  document.getElementById('check-list').innerHTML = checks.map(c =>
    `<li class="chk ${c.ok ? 'ok' : 'bad'}"><span class="chk-mark">${c.ok ? '✓' : '✗'}</span><span class="chk-name">${c.name}</span>${c.detail && !c.ok ? `<span class="chk-detail">${c.detail}</span>` : ''}</li>`
  ).join('');

  const note = document.getElementById('tamper-note');
  if (!tampered) { note.hidden = true; return; }
  note.hidden = false;
  const sigStillOk = checks.find(c => c.name.startsWith('Ed25519')).ok;
  note.innerHTML = sigStillOk
    ? `Notice the <strong>signature still checks out</strong> — it seals the list of fingerprints, not the values. Editing the number broke the link between the number and its own fingerprint. That is how a doctored result is caught even when the signature looks fine.`
    : `The signature no longer verifies either — the record has been altered.`;
}
