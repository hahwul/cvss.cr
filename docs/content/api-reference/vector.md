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
| `metric_order : Array(String)` | Every metric key this version defines, in canonical order. |
| `metric_code?(name : String) : String?` | Short-code for one metric, or `nil` when it is optional and unset. Raises `CVSS::Error` for a key the version does not define. |

## Concrete methods

| Method | Description |
|--------|-------------|
| `to_s : String` | Returns the canonical vector string. |
| `<=>(other : Vector) : Int32?` | Orders by `base_score`. Returns `nil` only on NaN (never produced by valid inputs). |
| `==(other : Vector) : Bool` | Default returns `false`; subclasses override with structural equality. |
| `inspect(io : IO) : Nil` | Outputs `#<CVSS::V3::Vector CVSS:3.1/... base=9.8>`. |
| `to_json(json : JSON::Builder) : Nil` | Emits an NVD-shaped JSON object. |
| `metric_value(name : String) : String` | Short-code for one metric. Unset optional metrics report the version's not-defined code (`X` for v3.x/v4.0, `ND` for v1.0/v2.0). |
| `to_h : Hash(String, String)` | Metric short-codes in canonical order. Optional metrics omitted when unset. |

All three are derived from `metric_code?`, so `metric_value`, `to_h` and `to_s` always agree on which metrics a vector carries.

## Top-level helpers

| Method | Description |
|--------|-------------|
| `CVSS.parse(input : String) : Vector` | Parses any supported version. Raises on failure. |
| `CVSS.parse?(input : String) : Vector?` | Returns `nil` instead of raising. |
| `CVSS.from_json(input : String \| IO) : Vector` | Reads a flat or NVD-nested JSON payload, or finds a `vectorString` anywhere in the document. |
| `CVSS.from_json?(input : String \| IO) : Vector?` | Returns `nil` instead of raising — including for input that is not JSON at all. |
| `CVSS.from_json_all(input : String \| IO) : Array(Vector)` | Every vector in the payload, in document order. |

## Scores across versions

`base_score`, `temporal_score` and `environmental_score` — and the matching `severity`, `temporal_severity` and `environmental_severity` — are answered by every vector class, so they can be called on a `CVSS::Vector` whose version is not known at compile time. CVSS v4.0 folds Threat and Environmental metrics into its single macro-vector score, so on a v4 vector `temporal_score` (an alias of `threat_score`) and `environmental_score` both return that one score; `nomenclature` says which label it carries.

## Equality semantics

Equality is *structural* and class-aware. Two vectors are `==` only when:

- They are the same concrete subclass (a v3 vector and a v4 vector are never equal), AND
- Every metric (including the parsed CVSS version for v3) compares equal.

This contract makes vectors safe to use as `Set` elements or `Hash` keys.

## Ordering semantics

`<=>` compares by `base_score` only. Two vectors with the same score are equal under `<=>` (so `cmp == 0`) but typically *not* `==`. This intentional split keeps "are these the same vulnerability description?" (`==`) separate from "which is more severe?" (`<=>`).
