+++
title = "Errors"
description = "Error types and exception handling"
weight = 6
+++

## Overview

All cvss.cr errors inherit from `CVSS::Error`, which itself inherits from `Exception`. You can catch the parent class for a single rescue clause or pattern-match on subclasses to distinguish failure modes.

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
| `CVSS::ParseError` | The vector string is malformed: empty input, missing required base metric(s), duplicate metric, unknown metric key, malformed segment, leading/trailing slash, or `from_json` payload missing a `vectorString` field. |
| `CVSS::InvalidMetricError` | A metric carries a value outside its allowed set (e.g. `AV:Q`). |
| `CVSS::UnknownVersionError` | The `CVSS:x.y/` prefix references a version this library does not implement (e.g. `CVSS:5.0/...`). |

## Non-CVSS exceptions

`CVSS.from_json` may also raise:

- `JSON::ParseException` — the input is not valid JSON.

This is **not** wrapped in `CVSS::Error`, since it is a structural failure of the input format rather than a CVSS-specific concern. Catch it explicitly when you need to distinguish "bad JSON" from "bad vector string".

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

`parse?` swallows every `CVSS::Error` subclass and returns `nil`. JSON-format errors from `CVSS.from_json` are still raised — there is no `from_json?` variant.
