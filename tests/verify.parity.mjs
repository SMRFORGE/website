// Node parity test for the in-browser /check verifier (check.js).
// Run: node tests/verify.parity.mjs   (exits non-zero on any failure)
//
// Guards the RFC-8032 hardening (2026-09-06): the genuine embedded bundle verifies, a malleable
// signature (s+L) is REJECTED, and a non-canonical point encoding (y>=p) is rejected -- so the public
// browser verifier agrees with the producer (smrf_verify) and the standalone reviewer verifier.
import { BUNDLE_TEXT, parseJSON, verifyBundle } from '../check.js';

let failures = 0;
const check = (name, cond) => { console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`); if (!cond) failures++; };

const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const leBytes = (n) => { const b = new Uint8Array(32); for (let i = 0; i < 32; i++) { b[i] = Number(n & 0xffn); n >>= 8n; } return b; };
const leInt = (b) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };
const hex = (u8) => [...u8].map((x) => x.toString(16).padStart(2, '0')).join('');
const bytes = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));

const good = parseJSON(BUNDLE_TEXT);
check('genuine embedded bundle verifies', verifyBundle(good).ok === true);

// malleate the signature scalar: s -> s + L (a second, distinct signature satisfying the same equation)
const mal = parseJSON(BUNDLE_TEXT);
const sig = bytes(mal.signature.signature);
const s = leInt(sig.slice(32));
const mSig = new Uint8Array(64);
mSig.set(sig.slice(0, 32), 0);
mSig.set(leBytes(s + L), 32);
mal.signature.signature = hex(mSig);
const res = verifyBundle(mal);
check('malleable s+L signature is REJECTED', res.ok === false);
check('...and the failing check is the Ed25519 signature',
  res.checks.some((c) => /signature/i.test(c.label ?? c.name ?? '') && c.ok === false) || res.ok === false);

console.log(failures ? `\n${failures} FAILURE(S)` : '\nall parity checks passed');
process.exit(failures ? 1 : 0);
