+++
title = "Scoring & Severity"
description = "Base, Temporal, Environmental scores, sub-scores, and the v4 macro vector"
weight = 3
+++

## Base score

Every Vector exposes a `base_score : Float64` and a `severity : CVSS::Severity`:

```crystal
v = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
v.base_score  # => 9.8
v.severity    # => CVSS::Severity::Critical
```

The qualitative `Severity` enum is unified across versions:

| Score      | Severity |
|------------|----------|
| 0.0        | None     |
| 0.1 – 3.9  | Low      |
| 4.0 – 6.9  | Medium   |
| 7.0 – 8.9  | High     |
| 9.0 – 10.0 | Critical |

CVSS v2.0 has no Critical band — `v2.severity` returns at most `High`.

## Temporal & Environmental scores (v2 / v3)

```crystal
v = CVSS::V3::Vector.parse(
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"
)
v.temporal_score       # => 9.1
v.environmental_score  # => 9.1  (no env metrics → falls back to temporal)
```

When environmental metrics are set, the modifier weights and scope-aware Impact formula kick in:

```crystal
v = CVSS::V3::Vector.parse(
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R" \
  "/CR:H/IR:H/AR:M/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:H/MI:N/MA:N"
)
v.base_score           # => 9.8
v.environmental_score  # => 6.3
```

CVSS v3.0 and v3.1 share the same RoundUp at the base level, but use different polynomials in the *modified* impact formula. The library handles both transparently.

## CVSS v4.0 — single score

CVSS v4.0 folds Threat (E) and Environmental metrics directly into the macro-vector lookup, so there is one combined score rather than a base / temporal / environmental triple:

```crystal
v = CVSS.parse(
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
)
v.base_score   # => 9.3
```

You can read the 6-character macro vector that drives the lookup:

```crystal
v.macro_vector  # => "000200"
```

## Sub-scores (v3.x)

For tooling and debugging, v3 vectors expose the intermediate ISS, Impact, and Exploitability sub-scores defined in the spec:

```crystal
v = CVSS::V3::Vector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
v.iss                       # => 0.9148...
v.impact_subscore           # => 5.873...
v.exploitability_subscore   # => 3.887...
```

## Severity from arbitrary scores

```crystal
CVSS::Severity.from_score(7.5)     # => CVSS::Severity::High
CVSS::Severity.from_v2_score(3.9)  # => CVSS::Severity::Low (CVSS v2 banding)
```

`Severity` is a normal Crystal enum, so it gets `<=>`, predicate methods (`vec.severity.critical?`), and string conversion (`vec.severity.to_s`) for free.
