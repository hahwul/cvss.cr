require "json"

# JSON serialization for CVSS vectors.
#
# `Vector#to_json` emits a payload modeled after the FIRST CVSS JSON Schema
# (https://www.first.org/cvss/cvss-v3.1.json) and the NVD CVE feed format,
# limited to the fields that round-trip cleanly:
#
# ```json
# {
#   "version": "3.1",
#   "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
#   "baseScore": 9.8,
#   "baseSeverity": "CRITICAL"
# }
# ```
#
# `CVSS.from_json(input)` accepts:
#   - A bare CVSS JSON object (`{"vectorString": "..."}`),
#   - An NVD-nested payload (`{"cvssData": {"vectorString": "..."}}`), or
#   - Any object or array with a `vectorString` somewhere inside it, which
#     covers a whole NVD API 2.0 response or CVE record unmodified — and a
#     bare list of them.
#
# and returns the parsed Vector. `CVSS.from_json_all(input)` returns every
# vector in the payload instead of just the first — an NVD record commonly
# scores one CVE under v2.0, v3.1 and v4.0 at once.
#
# Other JSON fields (baseScore, baseSeverity, etc.) are recomputed from the
# vectorString — they are never trusted from the input, so a tampered
# payload still produces a correctly-scored vector.
module CVSS
  abstract class Vector
    def to_json(json : ::JSON::Builder) : Nil
      json.object do
        write_json_fields(json)
      end
    end

    # Subclasses extend this to add version-specific fields (sub-scores,
    # temporal/environmental scores, etc.) within the same JSON object.
    protected def write_json_fields(json : ::JSON::Builder) : Nil
      json.field "version", version
      json.field "vectorString", to_s
      json.field "baseScore", base_score
      json.field "baseSeverity", severity_label(severity)
    end

    protected def severity_label(s : Severity) : String
      s.to_s.upcase
    end
  end

  # Read a Vector from a JSON string or IO.
  #
  # Two shapes are treated as the caller pointing straight at a CVSS object:
  # a `vectorString` at the top level, and one under `cvssData` (the
  # NVD/FIRST CVSS object shape). A malformed vector in either is an error —
  # the caller said that is the vector.
  #
  # Anything else is *searched*: the whole document is walked for a
  # `vectorString`, which is what lets a full NVD API 2.0 response or CVE
  # record work unmodified, since those bury the CVSS object several levels
  # down (`vulnerabilities[].cve.metrics.cvssMetricV31[].cvssData
  # .vectorString`). Because that is a search rather than a lookup, entries
  # it cannot use are skipped instead of raised on — a record can carry a
  # placeholder `""` or `null`, or a CVSS version this library does not
  # implement, right beside the vector the caller actually wants. The first
  # usable vector in document order wins.
  #
  # A payload commonly carries several — an NVD record usually scores a CVE
  # under v2.0, v3.1 *and* v4.0. Use `from_json_all` when you need all of
  # them, or want to pick by version yourself.
  def self.from_json(input : String | IO) : Vector
    json = ::JSON.parse(input)

    # A scalar or null cannot hold a vector at any depth. Reject it by shape,
    # which says more than "no vectorString field" would.
    unless json.as_h? || json.as_a?
      raise ParseError.new("JSON payload must be a JSON object")
    end

    if vs = explicit_vector_string(json)
      return parse(vs)
    end

    candidates = [] of String
    collect_vector_strings(json, candidates)
    candidates.each do |string|
      if vector = parse?(string)
        return vector
      end
    end

    raise ParseError.new("no vectorString field in JSON payload") if candidates.empty?

    # The document did hold candidates, none of them usable. Re-run the first
    # so the caller gets the real reason rather than "no vectorString field".
    parse(candidates.first)
  end

  # Every Vector in a JSON payload, in document order.
  #
  # Built for the NVD shapes that score one CVE several times over — an API
  # 2.0 response nests a `cvssData` object per CVSS version — where
  # `from_json` would hand back only the first.
  #
  # ```
  # vectors = CVSS.from_json_all(File.read("nvd_response.json"))
  # vectors.map(&.version)       # => ["4.0", "3.1", "2.0"]
  # vectors.max_by(&.base_score) # worst score across versions
  # ```
  #
  # Unlike `from_json`, a malformed or unsupported `vectorString` raises
  # rather than being skipped: a caller asking for *all* the vectors cannot
  # be handed a quietly short list. Values that are not strings at all are
  # still skipped — those are not vector strings to begin with. Returns an
  # empty array when the payload holds no `vectorString`.
  def self.from_json_all(input : String | IO) : Array(Vector)
    json = ::JSON.parse(input)
    strings = [] of String
    collect_vector_strings(json, strings)
    strings.map { |string| parse(string) }
  end

  # Non-raising `from_json` — returns nil when the input is not JSON, is
  # JSON of the wrong shape, carries no `vectorString`, or that string is
  # not a vector this library can parse.
  #
  # `from_json` itself lets `JSON::ParseException` through for input that
  # is not JSON at all (it pinpoints the offending line and column, which a
  # `CVSS::ParseError` could not), so a caller feeding it untrusted payloads
  # would otherwise have to rescue two unrelated exception hierarchies.
  #
  # ```
  # CVSS.from_json?(%({"vectorString": "CVSS:3.1/AV:N/…"})).try(&.base_score)
  # CVSS.from_json?("not-json") # => nil
  # ```
  def self.from_json?(input : String | IO) : Vector?
    from_json(input)
  rescue Error | ::JSON::ParseException
    nil
  end

  # The `vectorString` of a payload that *is* a CVSS object — top-level, or
  # wrapped in the `cvssData` key NVD and the FIRST schema use. Returns nil
  # when the payload is neither, leaving the caller to search it instead.
  #
  # A `cvssData` that is not an object is not a CVSS object either, so it
  # falls through to the search rather than aborting it.
  private def self.explicit_vector_string(json : ::JSON::Any) : String?
    # `JSON::Any#[]?` raises a bare `Exception` when the value it wraps is
    # not an object, so the payload is unwrapped with `as_h?` first.
    obj = json.as_h?
    return if obj.nil?

    if vs = obj["vectorString"]?
      return string_field(vs)
    end
    if nested = obj["cvssData"]?.try(&.as_h?)
      if vs = nested["vectorString"]?
        return string_field(vs)
      end
    end
    nil
  end

  # Depth-first walk collecting every string-valued `vectorString` into
  # `into`, in document order.
  #
  # Non-string values under that key are skipped rather than raised on. The
  # walk is a search across a whole document, so an unrelated or placeholder
  # `"vectorString": null` must not hide the real vector elsewhere in it;
  # `explicit_vector_string` still raises for the shapes where the caller
  # named the key themselves.
  private def self.collect_vector_strings(value : ::JSON::Any, into : Array(String)) : Nil
    if hash = value.as_h?
      hash.each do |key, child|
        if key == "vectorString"
          if string = child.as_s?
            into << string
          end
        else
          collect_vector_strings(child, into)
        end
      end
    elsif array = value.as_a?
      array.each { |child| collect_vector_strings(child, into) }
    end
  end

  # Coerce a `vectorString` JSON value to a String, raising `ParseError`
  # (never a raw TypeCastError) when it is null or a non-string type.
  private def self.string_field(value : ::JSON::Any) : String
    value.as_s? || raise ParseError.new("vectorString must be a string")
  end
end

module CVSS::V1
  class Vector < CVSS::Vector
    protected def write_json_fields(json : ::JSON::Builder) : Nil
      super
      if @e || @rl || @rc
        ts = temporal_score
        json.field "temporalScore", ts
        json.field "temporalSeverity", severity_label(Severity.from_v1_score(ts))
      end
      if @cdp || @td
        es = environmental_score
        json.field "environmentalScore", es
        json.field "environmentalSeverity", severity_label(Severity.from_v1_score(es))
      end
    end
  end
end

module CVSS::V2
  class Vector < CVSS::Vector
    protected def write_json_fields(json : ::JSON::Builder) : Nil
      super
      if @e || @rl || @rc
        ts = temporal_score
        json.field "temporalScore", ts
        json.field "temporalSeverity", severity_label(Severity.from_v2_score(ts))
      end
      if @cdp || @td || @cr || @ir || @ar
        es = environmental_score
        json.field "environmentalScore", es
        json.field "environmentalSeverity", severity_label(Severity.from_v2_score(es))
      end
    end
  end
end

module CVSS::V3
  class Vector < CVSS::Vector
    protected def write_json_fields(json : ::JSON::Builder) : Nil
      super
      json.field "exploitabilityScore", CVSS.round1(exploitability_subscore)
      json.field "impactScore", CVSS.round1(impact_subscore)

      if @e || @rl || @rc
        ts = temporal_score
        json.field "temporalScore", ts
        json.field "temporalSeverity", severity_label(Severity.from_score(ts))
      end

      if any_environmental_metric?
        es = environmental_score
        json.field "environmentalScore", es
        json.field "environmentalSeverity", severity_label(Severity.from_score(es))
      end
    end

    private def any_environmental_metric? : Bool
      !(@cr.nil? && @ir.nil? && @ar.nil? &&
        @mav.nil? && @mac.nil? && @mpr.nil? && @mui.nil? && @ms.nil? &&
        @mc.nil? && @mi.nil? && @ma.nil?)
    end
  end
end

module CVSS::V4
  class Vector < CVSS::Vector
    protected def write_json_fields(json : ::JSON::Builder) : Nil
      super
      # CVSS v4.0 has only a single score (threat/environmental folded in
      # via the macro vector). Expose the macro vector and nomenclature
      # classification for tooling.
      json.field "macroVector", macro_vector
      json.field "nomenclature", nomenclature.to_s
    end
  end
end
