+++
title = "Version Notes"
description = "Per-version quirks and spec compliance notes"
weight = 5
+++

## CVSS v2.0

- **No prefix in vector strings.** `CVSS.parse` recognises both prefix-less input and an explicit `CVSS:2.0/` prefix (some downstream tools emit the latter for symmetry with v3+).
- **Severity bands** map at most to `High` — there is no Critical band. `Severity::None` is returned for `0.0`, which is a small convenience extension over the strict spec (which only defines Low/Medium/High).
- **Multi-character codes**: `Au` (lowercase `u`), `CDP:LM`/`CDP:MH`, `RL:OF`/`RL:TF`, `RC:UC`/`RC:UR`, `E:POC` are all parsed and emitted exactly as written.
- Temporal and Environmental metrics are supported. `environmental_score` reduces to `0.0` when `TD:N`.

## CVSS v3.0 vs v3.1

Both versions are handled by the same `CVSS::V3::Vector` class. They share metric definitions and the base scoring formula. They differ in two places:

1. **RoundUp algorithm**
   - v3.0: `ceiling(input × 10) / 10`
   - v3.1: integer-space spec algorithm that avoids floating-point edge cases on values like `4.65`.

2. **Modified Impact polynomial (Environmental score, Scope:Changed)**
   - v3.0: `7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15`
   - v3.1: `7.52 × (ISS - 0.029) - 3.25 × (ISS × 0.9731 - 0.02)^13`

`vec.version` always returns the parsed version string (`"3.0"` or `"3.1"`); round-trips via `to_s` preserve it.

## CVSS v4.0

- **Single combined score.** Threat (E) and Environmental metrics are folded into a 6-character macro vector that drives a 270-entry lookup table; there are no separate temporal or environmental scores. `vec.environmental_score` and `vec.threat_score` are aliased to `base_score` for API symmetry.
- **Macro vector** is exposed via `vec.macro_vector` for tooling. Format: `EQ1 EQ2 EQ3 EQ4 EQ5 EQ6`, e.g. `"000200"`.
- **Subsequent System impacts**: `SC`, `SI`, `SA`. Modified counterparts (`MSI`, `MSA`) additionally accept `S` (Safety), which forces `EQ4 = 0`.
- **Provider Urgency (`U`)** uses full-word values (`Clear`, `Green`, `Amber`, `Red`).
- **Implementation source.** The lookup tables (`cvssLookup`, `maxComposed`, `maxSeverity`) and the depth-distance correction are ported verbatim from [FIRSTdotorg/cvss-v4-calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator) (BSD-2-Clause). Attribution is preserved in `src/cvss/v4/macro_vector.cr`.

## Cross-version comparisons

`Vector` includes `Comparable(Vector)` and orders by `base_score`, so `<`, `>`, and `sort` all work across versions. Equality, however, is *structural* — a v3 vector and a v4 vector are never `==` even when their scores are identical.
