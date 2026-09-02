# Changelog

## Unreleased

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
