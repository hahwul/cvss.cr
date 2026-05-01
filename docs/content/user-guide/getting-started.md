+++
title = "Getting Started"
description = "Install cvss.cr and parse your first CVSS vector"
weight = 1
+++

## Prerequisites

| Requirement | Version    |
|-------------|------------|
| Crystal     | >= 1.20.0  |

cvss.cr is pure Crystal with no native dependencies — it runs anywhere Crystal does.

## Installation

Add the dependency to your `shard.yml`:

```yaml
dependencies:
  cvss:
    github: hahwul/cvss.cr
```

Then install:

```bash
shards install
```

## Your First Program

Create `hello.cr`:

```crystal
require "cvss"

vec = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
puts vec.base_score   # => 9.8
puts vec.severity     # => Critical
puts vec.to_s         # => CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

Run it:

```bash
crystal run hello.cr
```

## Auto-detecting the version

`CVSS.parse` inspects the `CVSS:x.y/` prefix and dispatches to the right parser:

```crystal
CVSS.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").base_score
# => 9.3

CVSS.parse("AV:N/AC:L/Au:N/C:P/I:P/A:P").base_score
# => 7.5  (no prefix → CVSS v2.0)
```

## Non-raising parse

When validating user input, prefer `parse?` over wrapping `parse` in `begin/rescue`:

```crystal
if vec = CVSS.parse?(user_input)
  # use vec
else
  # malformed or unsupported version
end
```

## Next Steps

- **[Basic Usage](/user-guide/basic-usage/)** — typed metric access, serialization, equality
- **[Scoring & Severity](/user-guide/scoring/)** — base / temporal / environmental, sub-scores
- **[JSON & Filters](/user-guide/json-and-filters/)** — NVD-shaped JSON, classification helpers
