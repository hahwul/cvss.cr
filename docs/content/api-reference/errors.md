+++
title = "Errors"
description = "Error types and exception handling"
weight = 7
+++

## Overview

Every error cvss.cr raises for a vector string inherits from `CVSS::Error`, which itself inherits from `Exception`. You can catch the parent class for a single rescue clause or pattern-match on subclasses to distinguish failure modes. Two cases fall outside that hierarchy — input that is not JSON, and a NaN severity score — see [Non-CVSS exceptions](#non-cvss-exceptions).

## Hierarchy

```
Exception
  └── CVSS::Error
        ├── CVSS::ParseError
        ├── CVSS::InvalidMetricError
        └── CVSS::UnknownVersionError
```

## Error types

| Error | Raised when |
|-------|-------------|
| `CVSS::ParseError` | The vector string is malformed: empty input, missing required base metric(s), duplicate metric, unknown metric key, malformed segment, leading/trailing slash. Also every structural problem with a `from_json` payload that is still valid JSON: a scalar or `null` payload with no depth to search (`"…"`, `42`, `null`), no usable `vectorString` anywhere in the document, or a non-string `vectorString` under one of the two keys the caller named directly. |
| `CVSS::InvalidMetricError` | A metric carries a value outside its allowed set (e.g. `AV:Q`). |
| `CVSS::UnknownVersionError` | The `CVSS:x.y/` prefix references a version this library does not implement (e.g. `CVSS:5.0/...`). |

## Non-CVSS exceptions

`CVSS.from_json` may also raise:

- `JSON::ParseException` — the input is not valid JSON.

This is **not** wrapped in `CVSS::Error`, since it is a structural failure of the input format rather than a CVSS-specific concern. Catch it explicitly when you need to distinguish "bad JSON" from "bad vector string".

`JSON::ParseException` is the *only* non-`CVSS::Error` exception `from_json` raises. Once the input parses as JSON, every remaining problem — including a payload that is not an object — comes back as a `CVSS::ParseError`, so `rescue CVSS::Error | JSON::ParseException` covers untrusted input completely. `CVSS.from_json?` does exactly that and returns `nil` instead.

`CVSS::Severity.from_score` (and its `from_v2_score` / `from_v1_score` siblings) raises `ArgumentError` for a NaN score. Scores out of the 0.0–10.0 range saturate at the nearest band, but NaN compares false against every boundary and would otherwise be rated `Critical`, so it is refused instead. No score this library computes is ever NaN; the guard only matters when you call these class methods with your own number.

## Usage example

```crystal
begin
  vec = CVSS.parse(input)
rescue ex : CVSS::UnknownVersionError
  warn "Unsupported CVSS version: #{ex.message}"
rescue ex : CVSS::InvalidMetricError
  warn "Bad metric value: #{ex.message}"
rescue ex : CVSS::ParseError
  warn "Malformed vector: #{ex.message}"
rescue ex : CVSS::Error
  warn "CVSS error: #{ex.message}"
end
```

## Non-raising parse

When you only need to know *whether* parsing succeeded, prefer `parse?`:

```crystal
if vec = CVSS.parse?(user_input)
  # use vec
else
  # malformed or unsupported version
end
```

`parse?` swallows every `CVSS::Error` subclass and returns `nil`.

`CVSS.from_json?` is the equivalent for JSON payloads, and additionally swallows the `JSON::ParseException` that `from_json` raises for input that is not JSON at all:

```crystal
if vec = CVSS.from_json?(untrusted_payload)
  # use vec
else
  # not JSON, wrong shape, no vectorString, or an unparsable vector
end
```
