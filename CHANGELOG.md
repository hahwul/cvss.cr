# Changelog

## Unreleased

- Accept the `CVSS:` vector-string prefix in any case (`cvss:3.1/…`,
  `Cvss:4.0/…`). It previously fell through to the v2.0 parser, which
  reported `CVSS` as an unknown v2 metric. Metric keys and values remain
  case-sensitive, as the specs require.
- Report a prefix-less CVSS v3.x / v4.0 vector as such instead of failing
  as a v2.0 vector with an unknown metric. The `CVSS:x.y/` prefix is
  mandatory from v3.0 onward, and for v3.x it is the only thing that
  distinguishes v3.0 from v3.1, so it cannot be inferred.
- Report the version mismatch when a version-specific parser is handed
  another version's prefix (`CVSS::V2::Vector.parse("CVSS:3.1/…")`).
- `CVSS.from_json` now finds a `vectorString` anywhere in the payload, so a
  whole NVD API 2.0 response or CVE record works unmodified; previously only
  a top-level or `cvssData`-nested key was found. Top-level arrays — a bare
  list of records — are searched too. Because searching a document is not
  the same as being handed a CVSS object, entries the search cannot use (a
  placeholder `""`, a `null`, an unsupported CVSS version) are skipped
  rather than allowed to hide a usable vector beside them; the two flat
  shapes stay strict. A `cvssData` that is not an object now falls through
  to the search instead of raising, and a payload with candidates that all
  fail reports why the first one failed rather than "no vectorString field".
- Add `CVSS.from_json_all`, returning every vector in a payload — an NVD
  record commonly scores one CVE under v2.0, v3.1 and v4.0 at once. Unlike
  `from_json` it raises on a malformed `vectorString`, since a caller asking
  for all of them cannot be handed a quietly short list.
- Add `CVSS::V4::Vector#temporal_score` / `#temporal_severity` (aliases of
  the Threat accessors). The whole `temporal_*` / `environmental_*` family is
  now answered by every vector class, so it can be called on a
  `CVSS::Vector` of unknown version.
- Add `Vector#metric_code?`, which returns `nil` for an unset optional
  metric where `metric_value` returns the version's not-defined code — the
  two together distinguish an absent metric from one written as `E:X`.
- Derive `metric_value`, `to_h` and `to_s` from a single per-version metric
  table instead of three parallel ones, so they cannot drift apart.
- Fix `CVSS.parse` misrouting parenthesised CVSS v2.0 vectors — the form
  NVD's v2 calculator renders — to the v1.0 parser, where they failed with
  a misleading "invalid AV value" error. Version detection now keys off the
  v1-only `B` (Impact Bias) metric, and both parsers accept their notation
  with or without parentheses.
- Fix `CVSS::Severity.from_score` (and `from_v2_score` / `from_v1_score`)
  rating a NaN score as `Critical` / `High`; they now raise `ArgumentError`.
- Report an unknown CVSS v4.0 metric key as unknown rather than as the
  required metric it displaced, matching the v1/v2/v3 parsers.
- Add `CVSS.from_json?`, the non-raising counterpart to `CVSS.from_json`.

## v0.2.0

- Add CVSS v1.0 support (`CVSS::V1::Vector`): base, temporal, and
  environmental scoring, the Impact Bias metric, NVD's parenthesised vector
  notation, JSON serialization, and auto-detection in `CVSS.parse`.
- Fix CVSS v2 score rounding and clamp negative environmental scores.
- Clamp negative v3 impact subscores and harden `from_json` input handling.
- Harden parsing against malformed input and runtime crashes.
- Optimize CVSS v4 score computation.
- Require Crystal >= 1.21.0; add ameba lint baseline.

## v0.1.0

- First release
