# Changelog

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
