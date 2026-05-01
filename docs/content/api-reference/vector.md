+++
title = "Vector (abstract)"
description = "Abstract base class shared by every CVSS version"
weight = 1
+++

## `CVSS::Vector`

Abstract class. Every concrete vector (`CVSS::V2::Vector`, `CVSS::V3::Vector`, `CVSS::V4::Vector`) inherits from it and implements the abstract methods.

`CVSS::Vector` `include`s `Comparable(Vector)`, so any two vectors can be compared with `<`, `<=`, `>`, `>=`, `clamp`, `between?`, and used with `Array#sort`.

## Abstract methods

| Method | Description |
|--------|-------------|
| `version : String` | Returns `"2.0"`, `"3.0"`, `"3.1"`, or `"4.0"`. |
| `base_score : Float64` | Final, rounded base score in `0.0..10.0`. |
| `severity : Severity` | Qualitative rating (see Severity). |
| `to_s(io : IO) : Nil` | Writes the canonical vector string to `io`. |

## Concrete methods

| Method | Description |
|--------|-------------|
| `to_s : String` | Returns the canonical vector string. |
| `<=>(other : Vector) : Int32?` | Orders by `base_score`. Returns `nil` only on NaN (never produced by valid inputs). |
| `==(other : Vector) : Bool` | Default returns `false`; subclasses override with structural equality. |
| `inspect(io : IO) : Nil` | Outputs `#<CVSS::V3::Vector CVSS:3.1/... base=9.8>`. |
| `to_json(json : JSON::Builder) : Nil` | Emits an NVD-shaped JSON object. |

## Top-level helpers

| Method | Description |
|--------|-------------|
| `CVSS.parse(input : String) : Vector` | Parses any supported version. Raises on failure. |
| `CVSS.parse?(input : String) : Vector?` | Returns `nil` instead of raising. |
| `CVSS.from_json(input : String \| IO) : Vector` | Reads a flat or NVD-nested JSON payload. |

## Equality semantics

Equality is *structural* and class-aware. Two vectors are `==` only when:

- They are the same concrete subclass (a v3 vector and a v4 vector are never equal), AND
- Every metric (including the parsed CVSS version for v3) compares equal.

This contract makes vectors safe to use as `Set` elements or `Hash` keys.

## Ordering semantics

`<=>` compares by `base_score` only. Two vectors with the same score are equal under `<=>` (so `cmp == 0`) but typically *not* `==`. This intentional split keeps "are these the same vulnerability description?" (`==`) separate from "which is more severe?" (`<=>`).
