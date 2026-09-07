# Changelog

## v0.3.0

### Added

- `CVSS.from_json_all`, returning every vector in a payload — an NVD record
  commonly scores one CVE under v2.0, v3.1 and v4.0 at once.
- `CVSS.from_json?`, the non-raising counterpart to `CVSS.from_json`.
- `Vector#metric_code?`, which returns `nil` for an unset optional metric —
  telling an absent metric apart from one written as `E:X`.
- `CVSS::V4::Vector#temporal_score` / `#temporal_severity` (aliases of the
  Threat accessors), so the whole `temporal_*` / `environmental_*` family is
  answered by every vector class.

### Changed

- `CVSS.from_json` now finds a `vectorString` anywhere in the payload, so a
  whole NVD API 2.0 response or CVE record works unmodified; unusable
  entries (`""`, `null`, an unsupported version) are skipped rather than
  allowed to hide a usable vector beside them.
- Accept the `CVSS:` vector-string prefix in any case (`cvss:3.1/…`). Metric
  keys and values remain case-sensitive, as the specs require.
- Report a prefix-less v3.x / v4.0 vector, and a version-specific parser
  handed another version's prefix, as exactly that — both previously failed
  as v2.0 vectors with an unknown metric.
- Derive `metric_value`, `to_h` and `to_s` from a single per-version metric
  table instead of three parallel ones, so they cannot drift apart.

### Fixed

- `CVSS.parse` misrouting parenthesised v2.0 vectors — the form NVD's v2
  calculator renders — to the v1.0 parser, where they failed with a
  misleading "invalid AV value" error.
- `CVSS::Severity.from_score` (and `from_v2_score` / `from_v1_score`) rating
  a NaN score as `Critical` / `High`; they now raise `ArgumentError`.
- An unknown CVSS v4.0 metric key being reported as the required metric it
  displaced, unlike the v1/v2/v3 parsers.

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
