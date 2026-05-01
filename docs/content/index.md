+++
title = "cvss.cr"
description = "A Crystal implementation of the Common Vulnerability Scoring System"
+++

A Crystal library that parses, scores, and serializes CVSS vector strings.
Supports every released version of the standard.

| Version  | Status | Notes                                                |
|----------|--------|------------------------------------------------------|
| CVSS v2.0 | ✅     | Base + Temporal + Environmental                      |
| CVSS v3.0 | ✅     | Base + Temporal + Environmental (legacy RoundUp)     |
| CVSS v3.1 | ✅     | Base + Temporal + Environmental                      |
| CVSS v4.0 | ✅     | MacroVector lookup + EQ-distance correction (FIRST reference algorithm) |

## Quick Links

- **[Getting Started](/user-guide/getting-started/)** — installation and first use
- **[Basic Usage](/user-guide/basic-usage/)** — parse, score, severity
- **[Scoring & Severity](/user-guide/scoring/)** — base / temporal / environmental
- **[JSON & Filters](/user-guide/json-and-filters/)** — NVD-compatible serialization, classification helpers
- **[API Reference](/api-reference/vector/)** — all classes and methods

## Highlights

- Auto-detecting top-level `CVSS.parse(string)` — routes by `CVSS:x.y/` prefix.
- Strict spec-compliant scoring: v3.1 RoundUp and v4.0 macro-vector tables ported from FIRST's reference implementations.
- `Comparable(Vector)` — sort and compare by base score across versions.
- Structural equality + `hash` — vectors work as `Set` / `Hash` keys.
- NVD-shaped `to_json` and `from_json` for SBOM / SARIF tooling interop.
- 25+ classification helpers (`network?`, `requires_privileges?`, `scope_changed?`, …).
- Non-raising `parse?` — for input validation paths.

## Installation

Add the dependency to your `shard.yml`:

```yaml
dependencies:
  cvss:
    github: hahwul/cvss.cr
```

Then run:

```bash
shards install
```

## Quick Example

```crystal
require "cvss"

vec = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
vec.base_score   # => 9.8
vec.severity     # => CVSS::Severity::Critical
vec.network?     # => true
vec.to_json      # => {"version":"3.1","vectorString":"CVSS:3.1/...","baseScore":9.8, ...}
```
