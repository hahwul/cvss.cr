# cvss

A Crystal implementation of the [Common Vulnerability Scoring System
(CVSS)](https://www.first.org/cvss/) — parsing, scoring, and serialization
for vector strings.

Supported versions:

- **CVSS v2.0**
- **CVSS v3.0** / **v3.1**
- **CVSS v4.0** (full macro-vector lookup; algorithm ported from FIRST's
  reference calculator)

## Installation

Add the dependency to your `shard.yml`:

```yaml
dependencies:
  cvss:
    github: hahwul/cvss.cr
```

Then `shards install`.

## Usage

### Auto-detecting the version

`CVSS.parse` inspects the `CVSS:x.y/` prefix and dispatches to the
appropriate version-specific parser. Vector strings without a prefix are
treated as CVSS v2.0.

```crystal
require "cvss"

vec = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
vec.version      # => "3.1"
vec.base_score   # => 9.8
vec.severity     # => CVSS::Severity::Critical
vec.to_s         # => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

CVSS.parse("AV:N/AC:L/Au:N/C:P/I:P/A:P").base_score
# => 7.5

CVSS.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").base_score
# => 9.3
```

### Working with a specific version

You can also use the version-specific classes directly when you need access
to typed metric values, temporal scores, or modified-base overrides.

```crystal
v3 = CVSS::V3::Vector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C")
v3.base_score          # => 9.8
v3.temporal_score      # => 9.1
v3.environmental_score # => 9.1
v3.av                  # => CVSS::V3::AttackVector::Network
v3.severity            # => CVSS::Severity::Critical
```

### Building a vector programmatically

```crystal
v = CVSS::V3::Vector.new(
  av: CVSS::V3::AttackVector::Network,
  ac: CVSS::V3::AttackComplexity::Low,
  pr: CVSS::V3::PrivilegesRequired::None,
  ui: CVSS::V3::UserInteraction::None,
  s:  CVSS::V3::Scope::Unchanged,
  c:  CVSS::V3::Impact::High,
  i:  CVSS::V3::Impact::High,
  a:  CVSS::V3::Impact::High,
)
v.to_s         # => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
v.base_score   # => 9.8
```

### Non-raising parse

`CVSS.parse?` returns `nil` instead of raising on malformed input or
unsupported versions:

```crystal
if vec = CVSS.parse?(user_input)
  # use vec
end
```

The same `parse?` method is also available on each version-specific class:
`CVSS::V3::Vector.parse?(input)`, `CVSS::V4::Vector.parse?(input)`, etc.

### Equality, hashing, and ordering

Vectors are value types — two parsed vectors are `==` when they represent
the same CVSS string, and they hash consistently so they can be used as
`Hash` keys or `Set` elements:

```crystal
a = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
b = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
a == b      # => true
a.hash == b.hash # => true
```

Vectors are also `Comparable` by `base_score`, so sorting and
`min`/`max`/`<`/`>` all work — even across CVSS versions:

```crystal
vulns = inputs.map { |s| CVSS.parse(s) }
vulns.sort.last  # most severe vulnerability
```

Cross-version `==` always returns `false` (a v3 vector and a v4 vector are
never structurally equal even if their scores happen to match).

### Sub-scores (CVSS v3.x)

For tooling and debugging you can read the intermediate ISS, Impact and
Exploitability sub-scores:

```crystal
v3 = CVSS::V3::Vector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
v3.iss                       # => 0.9148...
v3.impact_subscore           # => 5.873...
v3.exploitability_subscore   # => 3.887...
```

### JSON serialization

`Vector#to_json` produces a payload aligned with the FIRST CVSS JSON Schema
and the NVD CVE feed format:

```crystal
require "json"

vec = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C")
puts vec.to_json
# {
#   "version": "3.1",
#   "vectorString": "CVSS:3.1/...",
#   "baseScore": 9.8,
#   "baseSeverity": "CRITICAL",
#   "exploitabilityScore": 3.9,
#   "impactScore": 5.9,
#   "temporalScore": 9.1,
#   "temporalSeverity": "CRITICAL"
# }
```

`CVSS.from_json` reads either a flat object or an NVD-nested
`{"cvssData": {...}}` payload, recomputing scores from the `vectorString`
(it never trusts a `baseScore` field in the input):

```crystal
CVSS.from_json(%({"vectorString": "CVSS:3.1/AV:N/..."})).base_score
CVSS.from_json(File.read("nvd_response.json"))
```

### Classification helpers

Every Vector exposes predicate methods for the most common filtering
queries — useful for triaging large vulnerability lists:

```crystal
vec.network?                   # AV:N
vec.local?                     # AV:L
vec.physical?                  # AV:P (v3, v4)
vec.requires_privileges?       # PR != N (v3, v4)
vec.requires_authentication?   # Au != N (v2)
vec.requires_user_interaction? # UI != N
vec.scope_changed?             # S:C (v3 only)
vec.impacts_subsequent_system? # any of SC/SI/SA != N (v4 only)
vec.impacts_confidentiality?
vec.impacts_integrity?
vec.impacts_availability?
```

### Hash export

`Vector#to_h` returns a `Hash(String, String)` of metric short-codes in
canonical order. Optional metrics are omitted when not set.

```crystal
CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F").to_h
# => {"AV" => "N", "AC" => "L", "PR" => "N", "UI" => "N",
#     "S" => "U", "C" => "H", "I" => "H", "A" => "H", "E" => "F"}
```

### MacroVector (CVSS v4.0)

```crystal
v4 = CVSS::V4::Vector.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
v4.macro_vector  # => "000200"
```

### Errors

All exceptions inherit from `CVSS::Error`:

- `CVSS::ParseError` — malformed vector string, missing required metrics, or
  duplicate metrics.
- `CVSS::InvalidMetricError` — a metric carries a value outside its allowed
  set (e.g. `AV:Q`).
- `CVSS::UnknownVersionError` — `CVSS:x.y/` prefix references a version this
  library does not implement.

## Severity

`CVSS::Severity` is a unified enum (`None`, `Low`, `Medium`, `High`,
`Critical`) used across all versions. CVSS v2 only defines Low/Medium/High,
so its `severity` method maps `0.0` to `None` and never returns `Critical`.

## Development

```sh
crystal spec
```

## License

MIT. The CVSS v4.0 macro-vector lookup tables and scoring algorithm are
ported from
[FIRSTdotorg/cvss-v4-calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator)
(BSD-2-Clause, Copyright FIRST, Red Hat, and contributors).

## Contributors

- [hahwul](https://github.com/hahwul) — creator and maintainer
