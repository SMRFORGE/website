// Node parity test for the in-browser /check verifier (check.js).
// Run: node tests/verify.parity.mjs   (exits non-zero on any failure)
//
// Guards two things:
//  1. RFC-8032 hardening (2026-09-06): the genuine embedded bundle verifies, a malleable signature (s+L)
//     is REJECTED, and a non-canonical point encoding (y>=p) is rejected.
//  2. Admissibility parity with evidence_verify.py v0.3.2 (2026-10-03): the browser verifier must not PASS
//     what the CLI (the challenge judge) rejects -- duplicate keys, a stapled top-level/host key, an extra
//     manifest section, or a named data-library with a null digest -- and altering the sealed number must
//     fail the hash-chain while the signature stays valid (the central "Break the Seal" invariant).
import { BUNDLE_TEXT, parseJSON, verifyBundle } from '../check.js';

let failures = 0;
const check = (name, cond) => { console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`); if (!cond) failures++; };
const chk = (res, re) => res.checks.find((c) => re.test(c.name)) || { ok: undefined };

const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const leBytes = (n) => { const b = new Uint8Array(32); for (let i = 0; i < 32; i++) { b[i] = Number(n & 0xffn); n >>= 8n; } return b; };
const leInt = (b) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };
const hex = (u8) => [...u8].map((x) => x.toString(16).padStart(2, '0')).join('');
const bytes = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
const fresh = () => parseJSON(BUNDLE_TEXT);

// --- 1. genuine bundle + RFC-8032 hardening ---
check('genuine embedded bundle verifies', verifyBundle(fresh()).ok === true);

const mal = fresh();
const sig = bytes(mal.signature.signature);
const s = leInt(sig.slice(32));
const mSig = new Uint8Array(64);
mSig.set(sig.slice(0, 32), 0);
mSig.set(leBytes(s + L), 32);
mal.signature.signature = hex(mSig);
const malRes = verifyBundle(mal);
check('malleable s+L signature is REJECTED', malRes.ok === false);
check('...and the failing check is the Ed25519 signature', chk(malRes, /Ed25519/).ok === false);

// --- 2. the central challenge invariant: a changed number fails, the signature stays valid ---
const t = fresh();
t.result.result['physics:openmc'].k_eff.raw = '1.1';
t.manifest.result.value.result['physics:openmc'].k_eff.raw = '1.1';
const tRes = verifyBundle(t);
check('changed k_eff fails overall', tRes.ok === false);
check('...the result section digest is what breaks', chk(tRes, /result section matches/).ok === false);
check('...and the Ed25519 signature still verifies (cannot be re-forged)', chk(tRes, /Ed25519/).ok === true);

// a mere reformat of the SAME value re-canonicalizes identically -> the browser preserves the literal, so
// it (correctly) rejects a non-canonical literal; the rules disclaim this as "the same number written
// differently" so it is not a claimable break either way.
const rf = fresh();
rf.result.result['physics:openmc'].k_eff.raw = '1.005220';
rf.manifest.result.value.result['physics:openmc'].k_eff.raw = '1.005220';
check('a non-canonical reformat of the same value does not verify in the browser', verifyBundle(rf).ok === false);

// --- 3. admissibility parity with evidence_verify.py v0.3.2 ---
let threw = false;
try { parseJSON('{"k_eff":1,"k_eff":2}'); } catch { threw = true; }
check('duplicate object keys are rejected at parse (no silent last-wins)', threw);

const top = fresh(); top.conclusion = 'approved for operation';
const topRes = verifyBundle(top);
check('a stapled top-level key is rejected', topRes.ok === false && chk(topRes, /No unsigned keys/).ok === false);

const sec = fresh(); sec.manifest.extra = { sha256: 'sha256:' + '0'.repeat(64), value: {} };
const secRes = verifyBundle(sec);
check('an extra manifest section is rejected', secRes.ok === false && chk(secRes, /exactly \{inputs/).ok === false);

const pin = fresh();
pin.manifest.provenance.value.data_library = 'ENDF/B-VIII.0';
pin.manifest.provenance.value.data_library_sha256 = null;
pin.reproducibility.data_library = 'ENDF/B-VIII.0';
pin.reproducibility.data_library_sha256 = null;
const pinRes = verifyBundle(pin);
check('a named data-library with a null digest is flagged by the pin check',
  pinRes.ok === false && chk(pinRes, /Data-library pin/).ok === false);

const hostB = fresh(); hostB.host.injected = 'attacker note';
const hostRes = verifyBundle(hostB);
check('an extra (unsigned) host key is rejected', hostRes.ok === false && chk(hostRes, /Host block/).ok === false);

const red = fresh(); red.redaction = { schema: 'smrforge.evidence_envelope.redaction.v1', withheld: ['inputs'] };
check('a redacted bundle fails closed in the browser (CLI-only feature)', verifyBundle(red).ok === false);

console.log(failures ? `\n${failures} FAILURE(S)` : '\nall parity checks passed');
process.exit(failures ? 1 : 0);
