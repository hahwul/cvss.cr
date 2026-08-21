+++
title = "Version Notes"
description = "Per-version quirks and spec compliance notes"
weight = 5
+++

## CVSS v1.0

- **No standardised vector string.** The FIRST v1.0 guide defines metrics and formulas but never a vector notation. This library uses NVD's — parentheses around the metric list, e.g. `(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)` — which is what every v1-era publisher emitted and what NVD documented at `nvd.nist.gov/cvss.cfm?vectorinfo`. `parse` also accepts the list without parentheses and with a `CVSS:1.0/` prefix; `to_s` always emits the canonical parenthesised form.
- **Impact Bias (`B`) is v1-only.** It re-weights the three impact sub-scores against one another (`Normal` splits them 0.333/0.333/0.333; a biased value gives the favoured impact 0.5 and the other two 0.25 each). v2.0 dropped the metric and reintroduced the idea as the environmental `CR`/`IR`/`AR` requirements. `B` is a *required* base metric — `parse` rejects a vector without it.
- **Binary base metrics.** `AV` is Remote/Local (no Adjacent Network), and `Au` is Required/Not-Required (no Single/Multiple split). `AV:R`, `Au:NR`, `RL:O`/`RL:T`, and `E:P` are all v1 spellings that mean something different — or nothing — in v2.0.
- **`RC:Uc`** (Uncorroborated) is written mixed-case in NVD's legend. Upper-case `RC:UC` — the code v2.0 later assigned to *Unconfirmed* — appears in the wild too, so both are accepted on input; `to_s` normalises to `Uc`.
- **No "Not Defined" values.** Unset temporal metrics score as the neutral 1.0, so `temporal_score` collapses to `base_score`; unset environmental metrics leave `environmental_score` equal to `temporal_score`. `TD:N` still legitimately zeroes the environmental score.
- **Official-Fix weighs 0.87.** The worked examples in the guide label it "(0.90)" in their summary tables, but only 0.87 — the value in the normative formula section — reproduces the 7.0 / 8.3 / 4.4 results printed beside them.
- **Severity bands** are NVD's Low/Medium/High; the v1.0 spec defines no qualitative ratings at all. `Severity::None` is returned for `0.0`, and `Critical` never appears.
- **Environmental vector notation is an extension.** NVD only ever published base and temporal vectors, so `CDP` and `TD` reuse the short codes v2.0 gave them. Vectors that omit them round-trip byte-for-byte either way.

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
- **Nomenclature (spec §6)**: `vec.nomenclature` returns one of `Base` (`CVSS-B`), `BaseThreat` (`CVSS-BT`), `BaseEnvironmental` (`CVSS-BE`), `BaseThreatEnvironmental` (`CVSS-BTE`) based on which optional metric groups carry meaningful (non-`X`) values. Supplemental metrics never affect the classification.
- **Implementation source.** The lookup tables (`cvssLookup`, `maxComposed`, `maxSeverity`) and the depth-distance correction are ported verbatim from [FIRSTdotorg/cvss-v4-calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator) (BSD-2-Clause). Attribution is preserved in `src/cvss/v4/macro_vector.cr`.

## Cross-version comparisons

`Vector` includes `Comparable(Vector)` and orders by `base_score`, so `<`, `>`, and `sort` all work across versions. Equality, however, is *structural* — a v3 vector and a v4 vector are never `==` even when their scores are identical.
