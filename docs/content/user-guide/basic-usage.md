+++
title = "Basic Usage"
description = "Parsing, typed access, equality, ordering, and serialization"
weight = 2
+++

## Parsing & version dispatch

```crystal
CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")     # → V3::Vector
CVSS.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")  # → V4::Vector
CVSS.parse("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")              # → V2::Vector
CVSS.parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")                       # → V2::Vector (no prefix)
```

## Typed metric access

Use the version-specific class to read individual metrics with strong typing:

```crystal
v = CVSS::V3::Vector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
v.av    # => CVSS::V3::AttackVector::Network
v.s     # => CVSS::V3::Scope::Unchanged
v.c     # => CVSS::V3::Impact::High
```

## Building a vector programmatically

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
v.to_s  # => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

## Round-tripping

`to_s` always produces the canonical FIRST ordering:

```crystal
input  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"
parsed = CVSS.parse(input)
parsed.to_s == input  # => true
```

## Equality and hashing

Vectors are value types — `==` is *structural* (same concrete class + same metrics) and they hash consistently:

```crystal
a = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
b = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
a == b              # => true
a.hash == b.hash    # => true

set = Set(CVSS::Vector).new
set << a
set << b
set.size            # => 1
```

Two vectors of different versions are never `==`, even when their scores happen to match.

## Ordering with Comparable

Vectors include `Comparable(Vector)` and compare by `base_score`, so sorting and `<` / `>` work — even across versions:

```crystal
vulns = inputs.map { |s| CVSS.parse(s) }
vulns.sort.last     # most severe vulnerability
vulns.min.base_score
```

## Hash export

`to_h` returns a `Hash(String, String)` of metric short-codes in canonical order:

```crystal
CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F").to_h
# => {"AV" => "N", "AC" => "L", "PR" => "N", "UI" => "N",
#     "S" => "U", "C" => "H", "I" => "H", "A" => "H", "E" => "F"}
```

Optional metrics that are not set are omitted.
