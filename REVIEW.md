# REVIEW.md — smrforge.io (the public-facing site)

This is the face a skeptical reviewer, journalist, or regulator sees first. The brand is honest evidence, so on this repo the failure that matters is **a public claim the evidence cannot back**. Optimize the review for overclaim and for the proof mechanisms being real. Start every review summary with a **count** of findings by severity.

## What failure looks like here
- **Overclaim (HIGH).** Any page text that says or implies more than the evidence proves. Specifically:
  - Implying results are **validated** against measured experiments. The public position is **code-verification vs OpenMC**, NOT measured-experiment validation. Flag "validated", "proven", "guarantee", "certified", "accurate" used in the truth sense.
  - Implying the seal proves the number is **physically correct**. The seal attests integrity + origin; reproduce attests re-derivability; neither attests correctness. Keep that boundary visible wherever a verdict/number appears.
  - Surfacing **gated / export-controlled benchmark anchors** as if they were ours to show (ICSBEP, IRPhEP, VHTRC, HTTR, MSRE, JAEA/ORNL measured data). These must not appear as measured anchors anywhere in the HTML/JS.
- **A faked proof mechanism (HIGH).** `check.html` / `check.js` must do REAL verification in the browser (recompute the section digests and run the Ed25519 check), never a hardcoded PASS/FAIL. A demo that only pretends to verify, on the honesty site, is the worst possible finding.
- **Stale or broken proof artifacts.** The Break-the-Seal dare points at a signed artifact / tag / verifier version that is current and valid; the published trust-root key fingerprint matches reality; the validation numbers of record are consistent. Flag: wrong `softwareVersion` / visible version badge, a moved tag, a stale verifier pin, a key fingerprint mismatch, dead/placeholder links.
- **Wording that reads as a correctness claim out of context.** A phrase a hostile reader could screenshot as "SMRFORGE proved X" even though it is disclaimed in the surrounding copy.

## Evidence a reviewer must cite
- For every overclaim finding, give **file:line and the exact quoted string**, and say why it exceeds integrity + origin + re-derivability.
- Run `node tests/verify.parity.mjs` — it must pass, and the embedded bundle must actually verify (this is how we know `check.js` is a real verifier, not a mock).
- Grep the whole site for overclaim terms (`validated`, `proven`, `guarantee`, `certified`, `accurate`) and for gated-benchmark names, and read every hit in context. Confirm the key fingerprint `cfb88804…`, the current engine/verifier versions, and the validation numbers of record (+108 pcm CE-MC floor; IAEA-2D −3) against reality.

## Nits and scope
Cap style nits at ~3. Tag Important / Nit / Pre-existing. The tagline and intentionally-strong phrasings are a judgment call, not an automatic blocker, IF they are defined/disclaimed in context — flag them as watch-items with the out-of-context risk, not as HIGH.

## Paths to skip (version strings that are CORRECT in context)
Do NOT "fix": the `engine_version` inside a REAL signed bundle in `check-bundle.js` (changing it breaks the hash/signature), historical/changelog narrative version strings, and the demo-key fingerprint (`069aba…`). A version string is only a finding when it is a stale CURRENT claim (e.g. JSON-LD `softwareVersion`, a product badge), not when it correctly describes a sealed bundle's own build.
