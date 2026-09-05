// Interactive evidence-bundle check. A from-scratch verifier that runs entirely in your browser:
// its own canonicalizer, SHA-256/512 via the platform's Web Crypto, and a hand-rolled RFC 8032
// Ed25519 -- no libraries, no network, no SMRFORGE code. A passing verify here is not the producer
// marking its own homework. Ported 1:1 from smrf_verify/verify.py.
import { BUNDLE_TEXT } from './check-bundle.js';

// SMRFORGE's pinned signing public key. It still equals the public DEMO identity, so a passing
// verify proves INTEGRITY (the bundle was not edited), not ORIGIN (that it came from SMRFORGE).
// This flips itself the day a real production key is generated out-of-repo and the bundles re-signed.
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

// ---------- hashing via Web Crypto (present in browsers and in Node's global crypto) ----------
const _enc = new TextEncoder();
const _hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
async function sha(str) { return 'sha256:' + _hex(await crypto.subtle.digest('SHA-256', _enc.encode(str))); }

// ---------- from-scratch RFC 8032 Ed25519 verify (BigInt field arithmetic; sha512 via Web Crypto) ----------
const Q = (2n ** 255n) - 19n;
const mod = (a) => ((a % Q) + Q) % Q;
function modpow(b, e, m) { b = ((b % m) + m) % m; let r = 1n; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
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
async function ed25519Verify(sig, msgStr, pub) {
  if (sig.length !== 64 || pub.length !== 32) return false;
  let r, a;
  try { r = decodepoint(sig.slice(0, 32)); a = decodepoint(pub); } catch { return false; }
  const s = leInt(sig.slice(32));
  const buf = new Uint8Array(32 + 32 + _enc.encode(msgStr).length);
  buf.set(sig.slice(0, 32), 0); buf.set(pub, 32); buf.set(_enc.encode(msgStr), 64);
  const k = leInt(new Uint8Array(await crypto.subtle.digest('SHA-512', buf)));
  const L = mul(BASE, s), Rk = add(r, mul(a, k));
  return L[0] === Rk[0] && L[1] === Rk[1];
}

// ---------- verify_bundle: returns a structured checklist so the UI can show each step ----------
async function verifyBundle(bundle) {
  const checks = [];
  const add_ = (name, ok, detail) => checks.push({ name, ok, detail });

  add_('Envelope schema recognised', bundle.schema === 'smrforge.evidence_envelope.v1', bundle.schema);

  const manifest = bundle.manifest || {}, sums = bundle.sha256sums || {};
  for (const side of ['inputs', 'result', 'provenance']) {
    const blk = manifest[side] || {};
    const rc = await sha(canon(blk.value));
    const ok = blk.sha256 === sums[side] && rc === blk.sha256;
    add_(`${side} section matches its sealed fingerprint`, ok, ok ? blk.sha256 : `recomputed ${rc} ≠ sealed ${sums[side]}`);
  }
  const rOk = canon(bundle.result) === canon(manifest.result?.value);
  add_('Readable result equals the hashed result', rOk);
  const pOk = canon(bundle.reproducibility) === canon(manifest.provenance?.value);
  add_('Readable provenance equals the hashed provenance', pOk);

  const rb = await sha(canon(sums));
  const sealOk = rb === bundle.bundle_sha256;
  add_('Bundle seal covers the whole fingerprint list', sealOk, sealOk ? rb : `recomputed ${rb} ≠ ${bundle.bundle_sha256}`);

  const sig = bundle.signature;
  let sigOk = false, sigDetail = '';
  if (!sig || sig.alg !== 'ed25519') sigDetail = 'no ed25519 signature';
  else if (sig.public_key !== PINNED_PUBKEY) sigDetail = 'not under the pinned key';
  else { sigOk = await ed25519Verify(hexToBytes(sig.signature), rb, hexToBytes(PINNED_PUBKEY)); sigDetail = sigOk ? 'valid' : 'does not verify'; }
  add_('Ed25519 signature over the seal is valid', sigOk, sigDetail);

  return { ok: checks.every(c => c.ok), checks };
}

// expose the pure core for a headless (Node) parity test
export { BUNDLE_TEXT, parseJSON, canon, verifyBundle, NumLit, PINNED_IS_DEMO };

// ======================================================================================
// UI wiring -- runs only in a browser; a Node import of the functions above skips all of this
// ======================================================================================
if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', initUI);
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

  async function run() {
    // apply current field values into the tree
    kNodes.forEach(n => { n.raw = kInput.value.trim() === '' ? '0' : kInput.value.trim(); });
    bundle.reproducibility.data_library_sha256 = dlInput.value;
    bundle.manifest.provenance.value.data_library_sha256 = dlInput.value;

    const tampered = kInput.value.trim() !== K0 || dlInput.value !== DL0;
    const { ok, checks } = await verifyBundle(bundle);
    renderVerdict(ok, checks, tampered);
  }

  document.getElementById('btn-verify').addEventListener('click', run);
  kInput.addEventListener('input', run);
  dlInput.addEventListener('input', run);
  document.getElementById('btn-reset').addEventListener('click', () => { kInput.value = K0; dlInput.value = DL0; run(); });

  // self-test in the console so a real-browser regression is visible
  (async () => {
    const fresh = parseJSON(BUNDLE_TEXT);
    const clean = await verifyBundle(fresh);
    fresh.result.result['physics:openmc'].k_eff.raw = '1.5';
    const dirty = await verifyBundle(fresh);
    console.info(`[check self-test] real=${clean.ok ? 'PASS' : 'FAIL'}  tampered=${dirty.ok ? 'PASS(!)' : 'caught'}`);
  })();

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

  // reproduce band: k +/- 3 sigma
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
