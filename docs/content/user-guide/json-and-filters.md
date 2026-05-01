+++
title = "JSON & Filters"
description = "NVD-shaped JSON serialization and classification helpers for filtering"
weight = 4
+++

## NVD-shaped JSON output

`Vector#to_json` produces a payload aligned with the FIRST CVSS JSON Schema and the NVD CVE feed format:

```crystal
require "json"

vec = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C")
puts vec.to_json
```

```json
{
  "version": "3.1",
  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C",
  "baseScore": 9.8,
  "baseSeverity": "CRITICAL",
  "exploitabilityScore": 3.9,
  "impactScore": 5.9,
  "temporalScore": 9.1,
  "temporalSeverity": "CRITICAL"
}
```

Per-version differences:

- **v2** and **v3.x** add `temporalScore`/`temporalSeverity` and `environmentalScore`/`environmentalSeverity` only when the corresponding optional metrics are present in the vector.
- **v3.x** always includes `exploitabilityScore` and `impactScore` (rounded to one decimal, matching NVD).
- **v4.0** adds `macroVector` instead of separate temporal/environmental fields.

## Reading JSON

`CVSS.from_json` accepts either:

- a flat object with a `vectorString` field, or
- an NVD-nested payload (`{"cvssData": {"vectorString": "..."}}`)

```crystal
CVSS.from_json(%({"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}))
# => CVSS::V3::Vector

CVSS.from_json(File.read("nvd_response.json"))
```

The library only trusts the `vectorString` — `baseScore` and similar fields in the input are ignored, and scores are recomputed from the parsed vector. This makes parsing safe against tampered or stale payloads.

## Round-tripping via JSON

```crystal
original    = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F")
reconstruct = CVSS.from_json(original.to_json)
reconstruct == original  # => true
```

## Classification helpers

Predicate methods make filtering large vulnerability lists ergonomic:

```crystal
vec.network?                   # AV:N
vec.adjacent_network?          # AV:A
vec.local?                     # AV:L
vec.physical?                  # AV:P    (v3, v4)
vec.requires_privileges?       # PR != N (v3, v4)
vec.requires_authentication?   # Au != N (v2)
vec.requires_user_interaction? # UI != N
vec.scope_changed?             # S:C    (v3 only)
vec.impacts_subsequent_system? # any of SC/SI/SA != N (v4 only)
vec.impacts_confidentiality?
vec.impacts_integrity?
vec.impacts_availability?
```

Severity predicates come for free from the `Severity` enum:

```crystal
vec.severity.critical?
vec.severity >= CVSS::Severity::High
```

## Filtering example

```crystal
vulns = inputs.map { |s| CVSS.parse(s) }

# All network-reachable, no-privilege issues sorted worst-first
high_risk = vulns
  .select { |v| v.responds_to?(:network?) && v.network? }
  .reject(&.requires_privileges?)
  .sort
  .reverse

# Anything that crosses scope or hits the subsequent system
crossing = vulns.select do |v|
  (v.is_a?(CVSS::V3::Vector) && v.scope_changed?) ||
    (v.is_a?(CVSS::V4::Vector) && v.impacts_subsequent_system?)
end
```
