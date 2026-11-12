require "json"

# JSON serialization for CVSS vectors.
#
# `Vector#to_json` emits the CVSS object FIRST's JSON schemas define
# (https://www.first.org/cvss/cvss-v2.0.json, -v3.0, -v3.1, -v4.0) — the
# shape of NVD's `cvssData` and of a CVE JSON 5 `cvssV2_0`..`cvssV4_0`.
# Besides the scores, every metric the vector carries is spelled out under
# the schema's property name and enum value (`attackVector: "NETWORK"`).
# A metric is emitted exactly when it appears in `vectorString`: an explicit
# `X` / `ND` becomes `"NOT_DEFINED"`, as NVD does, and an omitted one is
# left out, so the object never claims more than the vector says.
#
# ```json
# {
#   "version": "3.1",
#   "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
#   "baseScore": 9.8,
#   "baseSeverity": "CRITICAL",
#   "exploitabilityScore": 3.9,
#   "impactScore": 5.9,
#   "attackVector": "NETWORK",
#   "attackComplexity": "LOW",
#   "privilegesRequired": "NONE",
#   "userInteraction": "NONE",
#   "scope": "UNCHANGED",
#   "confidentialityImpact": "HIGH",
#   "integrityImpact": "HIGH",
#   "availabilityImpact": "HIGH"
# }
# ```
#
# A few fields sit outside the FIRST schemas and are kept as extensions,
# which the v2.0 and v3.x schemas permit (they do not forbid additional
# properties): `baseSeverity`, `temporalSeverity` and
# `environmentalSeverity` on v2.0 (NVD's severity bands — the v2 guide
# defines none, and NVD puts `baseSeverity` beside `cvssData`, not in it),
# and `exploitabilityScore` / `impactScore` on v3.x (NVD carries those
# beside `cvssData` too). FIRST's v4.0 schema sets
# `unevaluatedProperties: false` and, as of Revision 2, defines no threat
# or environmental score, so a v4 object carries the schema's properties
# only — `macro_vector` and `nomenclature` are methods, not JSON fields.
# v1.0 has no FIRST schema; its object keeps the score fields alone.
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

    # Writes each `{property, value}` pair whose metric the vector carries,
    # the value spelled as the schema's enum.
    protected def write_metric_fields(json : ::JSON::Builder, metrics : Tuple) : Nil
      metrics.each do |name, value|
        json.field name, schema_enum(value) if value
      end
    end

    # The FIRST schema's spelling of a metric value: `AdjacentNetwork` →
    # `"ADJACENT_NETWORK"`, `NotDefined` → `"NOT_DEFINED"`.
    protected def schema_enum(value : Enum) : String
      value.to_s.underscore.upcase
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
    json = parse_json(input)

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
    json = parse_json(input)
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

  # `JSON.parse`, with invalid UTF-8 in an `IO` payload reported as a
  # `ParseError`. Reading from an IO, the lexer decodes characters and
  # raises a bare `InvalidByteSequenceError` on a stray byte, which is
  # neither a `CVSS::Error` nor a `JSON::ParseException` and so would
  # escape `from_json?`. (A `String` payload never gets that far: its
  # bytes reach `parse`, which rejects them itself.)
  private def self.parse_json(input : String | IO) : ::JSON::Any
    ::JSON.parse(input)
  rescue ex : InvalidByteSequenceError
    raise ParseError.new("JSON payload is not valid UTF-8: #{ex.message}")
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
      write_metric_fields(json, {
        {"accessVector", @av},
        {"accessComplexity", @ac},
        {"authentication", @au},
        {"confidentialityImpact", @c},
        {"integrityImpact", @i},
        {"availabilityImpact", @a},
        {"exploitability", @e},
        {"remediationLevel", @rl},
        {"reportConfidence", @rc},
        {"collateralDamagePotential", @cdp},
        {"targetDistribution", @td},
        {"confidentialityRequirement", @cr},
        {"integrityRequirement", @ir},
        {"availabilityRequirement", @ar},
      })
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
      write_metric_fields(json, {
        {"attackVector", @av},
        {"attackComplexity", @ac},
        {"privilegesRequired", @pr},
        {"userInteraction", @ui},
        {"scope", @s},
        {"confidentialityImpact", @c},
        {"integrityImpact", @i},
        {"availabilityImpact", @a},
        {"exploitCodeMaturity", @e},
        {"remediationLevel", @rl},
        {"reportConfidence", @rc},
        {"confidentialityRequirement", @cr},
        {"integrityRequirement", @ir},
        {"availabilityRequirement", @ar},
        {"modifiedAttackVector", @mav},
        {"modifiedAttackComplexity", @mac},
        {"modifiedPrivilegesRequired", @mpr},
        {"modifiedUserInteraction", @mui},
        {"modifiedScope", @ms},
        {"modifiedConfidentialityImpact", @mc},
        {"modifiedIntegrityImpact", @mi},
        {"modifiedAvailabilityImpact", @ma},
      })

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
      write_metric_fields(json, {
        {"attackVector", @av},
        {"attackComplexity", @ac},
        {"attackRequirements", @at},
        {"privilegesRequired", @pr},
        {"userInteraction", @ui},
        {"vulnConfidentialityImpact", @vc},
        {"vulnIntegrityImpact", @vi},
        {"vulnAvailabilityImpact", @va},
        {"subConfidentialityImpact", @sc},
        {"subIntegrityImpact", @si},
        {"subAvailabilityImpact", @sa},
        {"exploitMaturity", @e},
        {"confidentialityRequirement", @cr},
        {"integrityRequirement", @ir},
        {"availabilityRequirement", @ar},
        {"modifiedAttackVector", @mav},
        {"modifiedAttackComplexity", @mac},
        {"modifiedAttackRequirements", @mat},
        {"modifiedPrivilegesRequired", @mpr},
        {"modifiedUserInteraction", @mui},
        {"modifiedVulnConfidentialityImpact", @mvc},
        {"modifiedVulnIntegrityImpact", @mvi},
        {"modifiedVulnAvailabilityImpact", @mva},
        {"modifiedSubConfidentialityImpact", @msc},
        {"modifiedSubIntegrityImpact", @msi},
        {"modifiedSubAvailabilityImpact", @msa},
        {"Safety", @s},
        {"Automatable", @au},
        {"Recovery", @r},
        {"valueDensity", @v},
        {"vulnerabilityResponseEffort", @re},
        {"providerUrgency", @u},
      })
    end

    # v4.0 spells three values differently from the generic mapping: `AV:A`
    # is `ADJACENT` (not v3's `ADJACENT_NETWORK`), `E:P` is
    # `PROOF_OF_CONCEPT`, and `N` on the modified subsequent-system metrics
    # is `NEGLIGIBLE` (spec §4.2; schema `modifiedSubCType` /
    # `modifiedSubIaType`), while unmodified `SC/SI/SA:N` stay `NONE`.
    protected def schema_enum(value : Enum) : String
      case value
      when AttackVector::AdjacentNetwork, ModifiedAttackVector::AdjacentNetwork
        "ADJACENT"
      when ExploitMaturity::POC
        "PROOF_OF_CONCEPT"
      when ModifiedSubsequentConfidentiality::None,
           ModifiedSubsequentIntegrity::None,
           ModifiedSubsequentAvailability::None
        "NEGLIGIBLE"
      else
        super
      end
    end
  end
end
