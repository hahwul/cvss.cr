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
# `CVSS.from_json(input)` accepts either:
#   - A bare CVSS JSON object (`{"vectorString": "..."}`) or
#   - An NVD-nested payload (`{"cvssData": {"vectorString": "..."}}`)
#
# and returns the parsed Vector. Other JSON fields (baseScore, baseSeverity,
# etc.) are recomputed from the vectorString — they are never trusted from
# the input, so a tampered payload still produces a correctly-scored vector.
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

  # Read a Vector from a JSON string or IO. Looks for a `vectorString` key,
  # either at the top level or nested under `cvssData` (NVD format).
  def self.from_json(input : String | IO) : Vector
    json = ::JSON.parse(input)
    if vs = extract_vector_string(json)
      parse(vs)
    else
      raise ParseError.new("no vectorString field in JSON payload")
    end
  end

  private def self.extract_vector_string(json : ::JSON::Any) : String?
    if vs = json["vectorString"]?
      return vs.as_s
    end
    if cvss_data = json["cvssData"]?
      if vs = cvss_data["vectorString"]?
        return vs.as_s
      end
    end
    nil
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
      json.field "exploitabilityScore", round1(exploitability_subscore)
      json.field "impactScore", round1(impact_subscore)

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

    private def round1(x : Float64) : Float64
      ((x * 10.0 + 0.5).floor) / 10.0
    end
  end
end

module CVSS::V4
  class Vector < CVSS::Vector
    protected def write_json_fields(json : ::JSON::Builder) : Nil
      super
      # CVSS v4.0 has only a single score (threat/environmental folded in
      # via the macro vector). Expose the macro vector for tooling.
      json.field "macroVector", macro_vector
    end
  end
end
