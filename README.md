# cvss

A Crystal implementation of the [Common Vulnerability Scoring System
(CVSS)](https://www.first.org/cvss/) — parsing, scoring, and serialization
for vector strings.

Supported versions:

- **CVSS v1.0** (NVD's parenthesised vector notation, including the
  v1-only Impact Bias metric)
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
treated as CVSS v2.0 — unless they carry the v1-only `B` (Impact Bias)
metric, which marks them as v1.0.

Both v1.0 and v2.0 vectors are accepted with or without the surrounding
parentheses NVD renders them in, so parentheses on their own say nothing
about the version — `(AV:N/AC:L/Au:N/C:P/I:P/A:P)` is v2.0 and
`(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)` is v1.0. `B` is mandatory in v1.0 and
defined by no later version, which keeps the two unambiguous.

The `CVSS:` prefix is matched case-insensitively — `cvss:3.1/...` parses
like `CVSS:3.1/...`, since lower- and mixed-case spellings turn up in real
feeds. Metric keys and values stay case-sensitive, as the specs require.

From v3.0 onward the `CVSS:x.y/` prefix is mandatory, and for v3.x it is
the only thing that separates v3.0 from v3.1. A prefix-less vector carrying
v3 or v4 metrics is therefore reported rather than guessed at:

```crystal
CVSS.parse("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
# CVSS::ParseError: vector carries CVSS v3.x metrics but no 'CVSS:3.0/' or
# 'CVSS:3.1/' prefix; ...
```

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

CVSS.parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)").base_score
# => 10.0
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

CVSS v1.0 lives in `CVSS::V1::Vector`. Its vector strings are the ones NVD
published between 2005 and 2007 — parenthesised, and carrying the v1-only
`B` (Impact Bias) metric, which re-weights the three impact sub-scores
against each other:

```crystal
v1 = CVSS::V1::Vector.parse("(AV:R/AC:L/Au:NR/C:P/I:P/A:C/B:A/E:F/RL:O/RC:C)")
v1.base_score          # => 8.5
v1.temporal_score      # => 7.0
v1.b                   # => CVSS::V1::ImpactBias::Availability
v1.severity            # => CVSS::Severity::High
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
`CVSS::V3::Vector.parse?(input)`, `CVSS::V4::Vector.parse?(input)`, etc.,
and `CVSS.from_json?` does the same for JSON payloads.

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

### Scores across versions

`base_score`, `temporal_score` and `environmental_score` — and the matching
`severity`, `temporal_severity` and `environmental_severity` — are answered
by every vector class, so they can be called on a `CVSS::Vector` whose
version you do not know:

```crystal
inputs.map { |s| CVSS.parse(s) }.each do |vec|
  puts "#{vec.version} #{vec.base_score} #{vec.temporal_score} (#{vec.severity})"
end
```

CVSS v4.0 folds Threat and Environmental metrics into the single macro-vector
score, so on a v4 vector `temporal_score` (an alias of `threat_score`) and
`environmental_score` both return that one score. `nomenclature` tells you
which label — `CVSS-B`, `CVSS-BT`, `CVSS-BE`, `CVSS-BTE` — the score carries.

### Sub-scores (CVSS v3.x)

For tooling and debugging you can read the intermediate ISS, Impact and
Exploitability sub-scores:

```crystal
v3 = CVSS::V3::Vector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
v3.iss                       # => 0.9148...
v3.impact_subscore           # => 5.873...
v3.exploitability_subscore   # => 3.887...
```

`impact_subscore` is floored at `0.0`: the Scope-Changed polynomial dips
slightly negative when nothing is impacted, a case `base_score` already
reports as `0.0`. Use `CVSS::V3::Score.impact(vector)` for the raw
unclamped value.

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

`CVSS.from_json` reads a flat object, an NVD-nested `{"cvssData": {...}}`
payload, or any document with a `vectorString` somewhere inside it — which
covers a whole NVD API 2.0 response or CVE record unmodified. Scores are
always recomputed from the `vectorString`; a `baseScore` field in the input
is never trusted:

```crystal
CVSS.from_json(%({"vectorString": "CVSS:3.1/AV:N/..."})).base_score
CVSS.from_json(File.read("nvd_response.json"))
```

A record commonly scores one CVE under several CVSS versions at once.
`CVSS.from_json` returns the first vector in document order;
`CVSS.from_json_all` returns them all, so you can pick:

```crystal
vectors = CVSS.from_json_all(File.read("nvd_response.json"))
vectors.map(&.version)       # => ["3.1", "2.0"]
vectors.max_by(&.base_score) # worst score across versions
```

`CVSS.from_json?` is the non-raising form — it returns `nil` for anything
`from_json` rejects, including input that is not JSON at all:

```crystal
CVSS.from_json?(untrusted_payload).try(&.base_score)
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

Single metrics come from `metric_value` (which reports the version's
"not defined" code — `X` for v3.x/v4.0, `ND` for v1.0/v2.0 — when the
metric is unset) or `metric_code?` (which returns `nil` instead, so you can
tell an unset metric from one explicitly written as `E:X`):

```crystal
vec = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X")
vec.metric_value("AV")  # => "N"
vec.metric_value("RL")  # => "X"  (unset)
vec.metric_code?("E")   # => "X"  (set, explicitly Not Defined)
vec.metric_code?("RL")  # => nil  (absent from the vector)
```

### MacroVector and Nomenclature (CVSS v4.0)

```crystal
v4 = CVSS::V4::Vector.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
v4.macro_vector       # => "000200"
v4.nomenclature.to_s  # => "CVSS-B"

# Per CVSS v4.0 spec §6, the label reflects which optional metric groups
# carry meaningful (non-X) values:
bte = CVSS::V4::Vector.parse(
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/MAV:P"
)
bte.nomenclature.to_s         # => "CVSS-BTE"
bte.threat_set?               # => true
bte.environmental_set?        # => true
```

### Errors

Every error this library raises for a vector string inherits from
`CVSS::Error`:

- `CVSS::ParseError` — malformed vector string, missing required metrics, or
  duplicate metrics.
- `CVSS::InvalidMetricError` — a metric carries a value outside its allowed
  set (e.g. `AV:Q`).
- `CVSS::UnknownVersionError` — `CVSS:x.y/` prefix references a version this
  library does not implement.

Two cases fall outside that hierarchy:

- `CVSS.from_json` lets a `JSON::ParseException` through when the input is
  not JSON at all — that error pinpoints the offending line and column,
  which a `CVSS::ParseError` could not. Use `CVSS.from_json?` if you would
  rather get `nil` than rescue both.
- `CVSS::Severity.from_score` (and its `from_v2_score` / `from_v1_score`
  siblings) raises `ArgumentError` for a NaN score. No score this library
  computes is ever NaN, so this only applies when you call these class
  methods with a number of your own.

## Severity

`CVSS::Severity` is a unified enum (`None`, `Low`, `Medium`, `High`,
`Critical`) used across all versions. CVSS v2 only defines Low/Medium/High,
so its `severity` method maps `0.0` to `None` and never returns `Critical`.
CVSS v1 defines no qualitative ratings at all; it reuses the same
Low/Medium/High bands NVD labelled v1 scores with.

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
