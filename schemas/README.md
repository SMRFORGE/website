# Published schemas

Files here are served at `https://smrforge.io/schemas/…` so that a schema's
`$id` resolves to the schema itself.

`smrforge.evidence_envelope.v1.schema.json` is a **verbatim copy** of
`schema/evidence_envelope.v1.schema.json` in the
[evidence-envelope-spec](https://gitlab.com/smrforge/evidence-envelope-spec)
repository, which remains authoritative. If you change it there, copy it here in
the same change — the two must stay byte-identical, because implementations
resolve the `$id` to this URL.
