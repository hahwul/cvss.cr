+++
title = "Severity"
description = "Qualitative severity rating shared across CVSS versions"
weight = 5
+++

## `CVSS::Severity`

A Crystal `enum` with five members:

```crystal
CVSS::Severity::None
CVSS::Severity::Low
CVSS::Severity::Medium
CVSS::Severity::High
CVSS::Severity::Critical
```

Because it is a regular Crystal enum, it gets predicate methods (`s.critical?`, `s.high?`, …), `<=>`, and `to_s` for free.

## Class methods

| Method | Description |
|--------|-------------|
| `Severity.from_score(score : Float64) : Severity` | Maps a CVSS v3.x or v4.0 base score to a rating. |
| `Severity.from_v2_score(score : Float64) : Severity` | Uses the legacy CVSS v2.0 banding (no Critical band). |

## v3.x / v4.0 banding

| Score      | Severity |
|------------|----------|
| 0.0        | None     |
| 0.1 – 3.9  | Low      |
| 4.0 – 6.9  | Medium   |
| 7.0 – 8.9  | High     |
| 9.0 – 10.0 | Critical |

## CVSS v2.0 banding

| Score      | Severity |
|------------|----------|
| 0.0        | None *(extension; spec says Low)* |
| 0.1 – 3.9  | Low      |
| 4.0 – 6.9  | Medium   |
| 7.0 – 10.0 | High     |

`0.0 → None` is an extension over the strict v2 spec for consistency with the unified Severity enum. Pass through `from_score` instead of `from_v2_score` if you need v3-style banding.

## Examples

```crystal
CVSS::Severity.from_score(9.8).critical?      # => true
CVSS::Severity.from_score(7.5) >= CVSS::Severity::High  # => true
CVSS::Severity.from_v2_score(7.0).to_s         # => "High"
```

## JSON output

`to_json` emits severity as the upper-cased name (`"NONE"`, `"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`) to match the FIRST CVSS JSON Schema and NVD CVE feed conventions.
