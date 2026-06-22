# 1. PAdES/CAdES interoperability, conformance, and trust-enforcement (Stage 1)

Date: 2026-06-22

## Status

Accepted

## Context

A comparative audit of `underskrift` against the EU DSS reference
implementation surfaced a cluster of issues where the library produced *self-consistent but
non-interoperable* output, silently under-delivered on requested behaviour, or
left a trust decision open. The findings were grouped into a work list
("U-items") and addressed together because they share test infrastructure and
touch overlapping modules (`core/incremental.rs`, `cms/builder.rs`,
`verify/integrity.rs`, `signer.rs`, `svt/validator.rs`).

The motivating defects:

1. **The incremental writer always emitted a classic `xref` table and dropped
   `/ID` and `/Encrypt`.** For PDF ≥ 1.5 sources that use cross-reference
   *streams* (the majority of modern PDFs), appending a classic table with
   `/Prev` pointing at a stream produced a structurally inconsistent file that
   strict readers — and DSS — reject; encrypted PDFs were corrupted outright.
2. **`pades_level`, `tsa_url`, and `certify` were accepted but never acted on.**
   Requesting B-LTA produced a plain B-B signature with no error; `certify`
   never produced a `/DocMDP`.
3. **No detached CAdES.** Only PAdES (PDF-embedded) signatures were possible;
   the CMS layer had no signature-timestamp, certificate-values, or
   revocation-values unsigned attributes, so no CAdES baseline level existed.
4. **The ECDSA signature OID was keyed off the curve, not the digest**, so a
   non-default curve/hash pairing (and all SHA-3 pairings) were mis-encoded.
5. **ByteRange verification did not bind the gap to the parsed `/Contents`,**
   and a final signature that did not reach EOF was treated as merely
   informational rather than an integrity failure.
6. **SVT validation accepted any `x5c` certificate** ("accepting for now") even
   when it was not trusted.
7. **No commitment-type or signature-policy signed attributes** for qualified
   signature use cases.

## Decision

This ADR records the Stage 1 changes as a single batch. Each item below was
implemented behind regression tests. The high-impact PDF output paths should be
validated with strict external readers such as DSS and poppler's `pdfsig` as part
of release qualification.

### U-1 — Cross-reference streams; preserve `/ID` and `/Encrypt`

`PdfMetadata` now captures the trailer `/ID`, `/Encrypt`, and whether the
source's latest cross-reference section is a stream
(`reference_table.cross_reference_type`). `IncrementalWriter::set_trailer_meta`
carries these into the update. When the source uses a cross-reference stream the
writer emits an **XRef stream** object (uncompressed, `/W [1 w2 2]`, grouped
`/Index`, self-referential entry) instead of a classic table; the classic path
preserves `/ID`/`/Encrypt`, groups xref subsections, and emits the free-list
head. A new xref-stream fixture locks in that signing an xref-stream input emits
an xref-stream incremental update and preserves trailer identity metadata.

### U-2 — Wire `pades_level` / `tsa_url` / `certify`; fail loudly

`PdfSigner::sign` now honours the requested level: B-B returns directly; **B-T**
appends a `/DocTimeStamp` via the configured TSA; **B-LT/B-LTA** and B-T without
a TSA return an explicit `PdfSignError::Configuration` instead of silently
downgrading. `certify` emits a real `/DocMDP`: the signature dictionary gains a
`/Reference` (SigRef → DocMDP transform with a `/P` permission and `/V 1.2`) and
the catalog gains `/Perms /DocMDP`. The high-level B-LT/B-LTA DSS-revision and
archive-timestamp orchestration is deferred (the composable primitives exist).

### U-3 — Enforce SVT `x5c` trust

`SvtValidator::verify_jwt` no longer trusts an inline `x5c` certificate on its
own. An empty trust set fails closed; otherwise the signing certificate must be
a configured anchor or chain to one, reusing the main
`chain_verify::verify_chain` path.

### U-4 — Detached CAdES baseline (`cms::cades`)

A new module provides standalone, PDF-independent CAdES building blocks:

- **B-B** via `sign_detached` (a new `CmsProfile::Cades` adds
   signing-certificate-v2 *and* signing-time);
- **B-T** via `signature_timestamp_attr` plus the `signature_value` helper and
   `add_unsigned_attributes`;
- **B-LT** building blocks via `certificate_values_attr` and
   `revocation_values_attr`.

`add_unsigned_attributes` is the composition primitive: it injects unsigned
attributes into the single `SignerInfo` of an existing CMS and re-encodes. A
high-level CAdES B-LT orchestration pipeline and B-LTA (archive-timestamp-v3 /
`ats-hash-index-v3`) are intentionally deferred.

### U-5 — Digest-driven ECDSA signature OID

`ecdsa_signature_oid` selects the OID from the digest (SHA-256/384/512 and
SHA3-256/384/512) rather than the curve. The built-in signer pairs ECDSA with
the curve-default hash, so output is unchanged for reachable configurations and
only corrected for custom signers. The `EcdsaP521` *enum variant* lives in
`tsp-ltv` and is out of scope here.

### U-6 — Bind ByteRange to `/Contents`; enforce final-signature EOF coverage

`verify_byte_range_ex` decodes the hex in the ByteRange gap and requires it to
equal the parsed `/Contents` (defeating a wrapping attack that points the
ByteRange at a decoy token), and, for the final signature, treats failure to
reach EOF as an integrity error. A DSS-build object-ID collision test guards
against independent ID allocation.

### U-8 — Commitment-type and signature-policy signed attributes

`PdfCmsBuilder` and `SigningOptions` gained `commitment_type` (the six
`id-cti-ets-*` types) and `signature_policy` (`sigPolicyId` + `OtherHashAlgAndValue`
+ optional SPURI), emitted as the ETSI `commitment-type-indication` and
`signature-policy-identifier` signed attributes. For PAdES, the signer now
rejects configurations that combine these CMS attributes with the PDF `/Reason`
entry, matching DSS' baseline requirement that the semantics live in the signed
CMS attribute rather than in the unsigned PDF dictionary field.

## Consequences

- **Interoperability:** xref-stream sources are updated using xref streams,
  certified signatures emit the required DocMDP structures, and the new signed
  attributes are encoded in CMS. Trailer `/ID` and `/Encrypt` are preserved
  structurally.
- **No silent under-delivery:** an unmet conformance request now errors rather
  than returning a weaker signature.
- **New surface:** `cms::cades` (re-exported as `underskrift::cades`),
  `CmsProfile::Cades`, `CommitmentType`, `SignaturePolicy`,
  `DocMdpPermissions`, `SigningOptions::{commitment_type, signature_policy,
  certify_permissions}`, and `PdfSignError::Configuration`. These are additive
  for ordinary builder-style use, but may require source updates for external
  code that constructs `SigningOptions` with exhaustive struct literals or
  exhaustively matches `CmsProfile`.
- **Deferred (follow-on), explicitly tracked:** SVT → in-house `jose-rs`
  migration; high-level PAdES B-LT/B-LTA orchestration; CAdES-B-LTA (ATSv3);
  `EcdsaP521` (requires the `tsp-ltv` enum). Each is gated behind an explicit
  error or documented as not-yet-implemented rather than failing silently.
- **Encrypted PDFs:** `/Encrypt` is now preserved structurally, but new objects
  are still written in clear; full encrypted-document signing remains out of
  scope and should be treated as unsupported until addressed.
