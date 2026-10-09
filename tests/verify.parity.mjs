// Node parity test for the in-browser /check verifier (check.js).
// Run: node tests/verify.parity.mjs   (exits non-zero on any failure)
//
// Guards two things:
//  1. RFC-8032 hardening (2026-09-06): the genuine embedded bundle verifies, a malleable signature (s+L)
//     is REJECTED, and a non-canonical point encoding (y>=p) is rejected.
//  2. Admissibility parity with evidence_verify.py v0.3.2 (2026-10-03): the browser verifier must not PASS
//     what the CLI (the challenge judge) rejects -- duplicate keys, a stapled top-level key, an extra
//     manifest section, or a named data-library with a null digest -- and altering the sealed number must
//     fail the hash-chain while the signature stays valid (the central "Break the Seal" invariant).
//  3. Parity-hardening S1-S6 + timestamp/result-core shape (evidence-verifier v0.3.3, 2026-10-04): a
//     stapled signature-block key, a bad signature.message, a wrong-typed redaction field, unpinned+null
//     digest, a malformed timestamp block, a result core missing a required field, and a malformed JSON
//     document (trailing data, bad literal, NaN) must all FAIL -- while a well-formed timestamp and the
//     genuine bundle still PASS.
//  4. ADR-040 (2026-10-09): the unsigned top-level `host` block is RETIRED. The genuine embedded bundle
//     carries none, and a host block of ANY shape (the old well-formed triple included) is rejected as an
//     unsigned top-level key, in lock-step with smrf_verify -- the minting runtime is read only from the
//     signed provenance.toolchain.
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

const hostB = fresh(); hostB.host = { injected: 'attacker note' };
const hostRes = verifyBundle(hostB);
check('an unsigned host key is rejected (the host block itself is retired, ADR-040)',
  hostRes.ok === false && chk(hostRes, /No unsigned keys/).ok === false);

const red = fresh(); red.redaction = { schema: 'smrforge.evidence_envelope.redaction.v1', withheld: ['inputs'] };
check('a redacted bundle fails closed in the browser (CLI-only feature)', verifyBundle(red).ok === false);

// --- 4. parity-hardening S1-S6 + timestamp / result-core shape (fix-spec 2026-10-04, verifier v0.3.3) ---
// Each variant is cut from the GENUINE production-signed bundle so the Ed25519 signature still verifies;
// only the new shape check may catch it. That is the false-attestation class these checks close.
const sigOnly = (res) => chk(res, /Ed25519/).ok === true;

// S1: a stapled signature-block key (rides unsigned next to a genuine signature)
const s1 = fresh(); s1.signature.attestation = 'APPROVED BY THE US NRC';
const s1Res = verifyBundle(s1);
check('S1: a stapled signature-block key is rejected (signature itself still verifies)',
  s1Res.ok === false && chk(s1Res, /Signature block carries only/).ok === false && sigOnly(s1Res));
const s1b = fresh(); s1b.signature.identity = 'smrforge';
check('S1: the retired signature.identity key is rejected like any other extra key',
  chk(verifyBundle(s1b), /Signature block carries only/).ok === false);

// S2: signature.message must be exactly "bundle_sha256"
const s2 = fresh(); s2.signature.message = 'manifest';
const s2Res = verifyBundle(s2);
check('S2: a signature.message other than "bundle_sha256" is rejected',
  s2Res.ok === false && chk(s2Res, /Signature message is bound/).ok === false && sigOnly(s2Res));
const s2b = fresh(); delete s2b.signature.message;
check('S2: a missing signature.message is rejected', chk(verifyBundle(s2b), /Signature message is bound/).ok === false);

// S4 (retired by ADR-040): `host` is no longer an allowed unsigned surface at all. The exact triple the
// retired producer wrote (python_version / python_impl / platform) is an unsigned duplicate of the signed
// provenance.toolchain, so it fails as an unexpected top-level key while the signature still verifies --
// the same verdict smrf_verify gives (conformance vector invalid/unsigned_host_block.json).
check('ADR-040: the genuine embedded bundle carries no host block', !('host' in fresh()));
const s4 = fresh(); s4.host = { python_version: '3.12.0rc3', python_impl: 'CPython', platform: 'Windows' };
const s4Res = verifyBundle(s4);
check('ADR-040: the retired well-formed host triple is rejected as an unsigned top-level key (signature still verifies)',
  s4Res.ok === false && chk(s4Res, /No unsigned keys/).ok === false && sigOnly(s4Res));
const s4b = fresh(); s4b.host = { platform: { conclusion: 'approved for operation' } };
check('ADR-040: a host block smuggling a non-string claim is rejected the same way', chk(verifyBundle(s4b), /No unsigned keys/).ok === false);
const s4c = fresh(); s4c.host = 'Linux';
check('ADR-040: a non-object host is rejected the same way', chk(verifyBundle(s4c), /No unsigned keys/).ok === false);
check('ADR-040: no "Host block" check line remains in the checklist', verifyBundle(fresh()).checks.every((c) => !/Host block/.test(c.name)));

// S5 (superseded by ADR-041): the redaction record is exactly {schema, withheld, parent_bundle_sha256},
// all required and prose-free; `reason` / `caveats` are rejected whatever their type.
const redOk = () => ({ schema: 'smrforge.evidence_envelope.redaction.v1', withheld: ['inputs'], parent_bundle_sha256: fresh().bundle_sha256 });
const s5a = fresh(); s5a.redaction = { ...redOk(), reason: { conclusion: 'approved' } };
const s5aRes = verifyBundle(s5a);
check('ADR-041: a (mistyped) redaction.reason is rejected as an unexpected key',
  s5aRes.ok === false && chk(s5aRes, /Redaction record/).ok === false && /unexpected keys.*reason/.test(chk(s5aRes, /Redaction record/).detail));
const s5a2 = fresh(); s5a2.redaction = { ...redOk(), reason: 'WITHHELD AT NRC DIRECTION; RESULT ACCEPTED' };
check('ADR-041: the self-verified attack -- a well-typed free-text redaction.reason -- is rejected as an unexpected key',
  /unexpected keys.*reason/.test(chk(verifyBundle(s5a2), /Redaction record/).detail));
const s5b = fresh(); s5b.redaction = { ...redOk(), caveats: 'approved' };
check('ADR-041: redaction.caveats is rejected (removed from the format)', /unexpected keys.*caveats/.test(chk(verifyBundle(s5b), /Redaction record/).detail));
const s5c = fresh(); s5c.redaction = { ...redOk(), caveats: ['ok', 7] };
check('ADR-041: a redaction.caveats list is rejected too', /unexpected keys.*caveats/.test(chk(verifyBundle(s5c), /Redaction record/).detail));
const s5d = fresh(); s5d.redaction = { schema: 'smrforge.evidence_envelope.redaction.v1', withheld: ['inputs'] };
check('ADR-041: a redaction record without parent_bundle_sha256 is rejected (required)',
  /missing required keys.*parent_bundle_sha256/.test(chk(verifyBundle(s5d), /Redaction record/).detail));
const s5e = fresh(); s5e.redaction = { ...redOk(), parent_bundle_sha256: 'approved' };
check('ADR-041: a malformed parent_bundle_sha256 is rejected', /not a well-formed sha256/.test(chk(verifyBundle(s5e), /Redaction record/).detail));
const s5f = fresh(); s5f.redaction = { ...redOk(), parent_bundle_sha256: 'sha256:' + '0'.repeat(64) };
check('ADR-041: a parent_bundle_sha256 that is not this bundle\'s seal is rejected', /does not match/.test(chk(verifyBundle(s5f), /Redaction record/).detail));
const s5ok = fresh(); s5ok.redaction = redOk();
const s5okRes = verifyBundle(s5ok);
check('ADR-041 control: the prose-free three-key redaction record passes the shape check (and still fails closed as CLI-only)',
  chk(s5okRes, /Redaction record/).ok === true && s5okRes.ok === false);

// S6: the unpinned+null exception is gone -- "unpinned" needs a real digest like any other name
const s6 = fresh();
for (const pv of [s6.manifest.provenance.value, s6.reproducibility]) { pv.data_library = 'unpinned'; pv.data_library_sha256 = null; }
const s6Res = verifyBundle(s6);
check('S6: "unpinned" with a null digest is rejected by the pin check', s6Res.ok === false && chk(s6Res, /Data-library pin/).ok === false);
const s6b = fresh();
for (const pv of [s6b.manifest.provenance.value, s6b.reproducibility]) { pv.data_library = 'unpinned'; delete pv.data_library_sha256; }
check('S6: "unpinned" with a MISSING digest is rejected', chk(verifyBundle(s6b), /Data-library pin/).ok === false);
const s6c = fresh();
for (const pv of [s6c.manifest.provenance.value, s6c.reproducibility]) { pv.data_library_sha256 = 'sha256:' + 'G'.repeat(64); }
check('S6: a malformed (non-hex) digest is rejected', chk(verifyBundle(s6c), /Data-library pin/).ok === false);

// timestamp shape (ADR-041): exactly {format, token}, both required, format rfc3161, token strict-base64 DER
// (first decoded byte 0x30 -> base64 'MI'), <= 200000 chars. `tsa` is retired. The token is NOT verified here.
const goodTs = { format: 'rfc3161', token: 'MIIBAgMEBQ==' };
const tsOk = fresh(); tsOk.timestamp = { ...goodTs };
const tsOkRes = verifyBundle(tsOk);
check('timestamp control: a well-formed {format, token} RFC 3161 timestamp block still PASSES', tsOkRes.ok === true);
check('timestamp: the pass line says shape only, NOT verified here',
  /NOT verified here/.test(chk(tsOkRes, /Timestamp block/).name) && /NOT verified here/.test(chk(tsOkRes, /Timestamp block/).detail));
const tsAttack = fresh(); tsAttack.timestamp = { tsa: 'REVIEWED AND ACCEPTED BY THE US NRC', token: '***APPROVED***' };
const tsAttackRes = verifyBundle(tsAttack);
check('ADR-041: the self-verified timestamp attack (prose tsa + prose token) now FAILS while the signature still verifies',
  tsAttackRes.ok === false && chk(tsAttackRes, /Timestamp block/).ok === false && sigOnly(tsAttackRes));
const tsTsa = fresh(); tsTsa.timestamp = { ...goodTs, tsa: 'https://freetsa.org/tsr' };
check('ADR-041: the retired tsa key is rejected as an unexpected key', /unexpected timestamp keys.*tsa/.test(chk(verifyBundle(tsTsa), /Timestamp block/).detail));
const tsNoTok = fresh(); tsNoTok.timestamp = { format: 'rfc3161' };
check('ADR-041: a timestamp without token is rejected (required)', /missing required keys.*token/.test(chk(verifyBundle(tsNoTok), /Timestamp block/).detail));
const tsNoFmt = fresh(); tsNoFmt.timestamp = { token: goodTs.token };
check('ADR-041: a timestamp without format is rejected (required)', /missing required keys.*format/.test(chk(verifyBundle(tsNoFmt), /Timestamp block/).detail));
const tsText = fresh(); tsText.timestamp = { format: 'rfc3161', token: 'QVBQUk9WRUQgQlkgVEhFIFVTIE5SQw==' };
check('ADR-041: a token that is base64 of text (not DER) is rejected', /not a strict-base64 DER token/.test(chk(verifyBundle(tsText), /Timestamp block/).detail));
const tsPlace = fresh(); tsPlace.timestamp = { format: 'rfc3161', token: 'MIIE PLACEHOLDER-base64' };
check('ADR-041: the old spaced placeholder token is rejected', /not a strict-base64 DER token/.test(chk(verifyBundle(tsPlace), /Timestamp block/).detail));
const tsPad = fresh(); tsPad.timestamp = { format: 'rfc3161', token: 'MIIBAgMEBQ=' };
check('ADR-041: bad base64 padding is rejected', /not a strict-base64 DER token/.test(chk(verifyBundle(tsPad), /Timestamp block/).detail));
const tsA = fresh(); tsA.timestamp = { ...goodTs, conclusion: 'APPROVED' };
const tsARes = verifyBundle(tsA);
check('timestamp: an extra (unsigned) key is rejected', tsARes.ok === false && chk(tsARes, /Timestamp block/).ok === false && sigOnly(tsARes));
const tsB = fresh(); tsB.timestamp = { ...goodTs, token: { url: 'x' } };
check('timestamp: a non-string value is rejected', chk(verifyBundle(tsB), /Timestamp block/).ok === false);
const tsC = fresh(); tsC.timestamp = { ...goodTs, format: 'pgp' };
check('timestamp: a format other than rfc3161 is rejected', chk(verifyBundle(tsC), /Timestamp block/).ok === false);
const tsD = fresh(); tsD.timestamp = { ...goodTs, token: 'MI' + 'A'.repeat(200002) };
check('timestamp: an oversize token (> 200000 chars) is rejected', /too large/.test(chk(verifyBundle(tsD), /Timestamp block/).detail));
const tsE = fresh(); tsE.timestamp = 'stapled';
check('timestamp: a non-object timestamp is rejected', chk(verifyBundle(tsE), /Timestamp block/).ok === false);

// result core: every result.v1 required field must be present
for (const field of ['schema', 'schema_version', 'result', 'fidelity', 'verdict']) {
  const rc = fresh(); delete rc.result[field]; delete rc.manifest.result.value[field];
  const rcRes = verifyBundle(rc);
  check(`result core: a missing required field "${field}" is rejected`, rcRes.ok === false && chk(rcRes, /Result core carries/).ok === false);
}

// strict JSON parse: a malformed document throws cleanly (the verdict path surfaces that as a FAIL)
const throws = (txt) => { try { parseJSON(txt); return false; } catch { return true; } };
check('parse: the genuine bundle text still parses', !throws(BUNDLE_TEXT));
check('parse: trailing data after the document is rejected', throws(BUNDLE_TEXT + ' {"conclusion":"approved"}'));
check('parse: a bad literal is rejected', throws('{"a": tru}') && throws('{"a": nul}') && throws('{"a": True}'));
check('parse: NaN / Infinity are rejected', throws('{"a": NaN}') && throws('{"a": Infinity}') && throws('{"a": -Infinity}'));
check('parse: a missing colon / comma / bracket is rejected', throws('{"a" 1}') && throws('{"a":1 "b":2}') && throws('[1,2') && throws('{"a":1'));
check('parse: an unterminated string and a bad escape are rejected', throws('{"a":"x') && throws('{"a":"\\q"}') && throws('{"a":"\\u12G4"}'));
check('parse: a raw control character inside a string is rejected', throws('{"a":"x\ny"}'));
check('parse: a well-formed document with 30.0 keeps its literal', parseJSON('{"k": 30.0}').k.raw === '30.0');

console.log(failures ? `\n${failures} FAILURE(S)` : '\nall parity checks passed');
process.exit(failures ? 1 : 0);
