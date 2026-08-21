module CVSS
  # Top-level dispatcher that routes a vector string to the right
  # version-specific parser by inspecting the `CVSS:x.y/` prefix.
  module Parser
    extend self

    # CVSS v1.0 and v2.0 have no prefix; v3.0/v3.1/v4.0 all use a
    # `CVSS:x.y/` prefix.
    PREFIX_RE = /\ACVSS:(\d+\.\d+)\//

    # Impact Bias is a v1.0-only metric — no later version defines a `B`
    # key — so its presence identifies an unparenthesised v1 vector that
    # would otherwise be mistaken for v2.0.
    V1_IMPACT_BIAS_RE = /(?:\A|\/)B:/

    def parse(input : String) : Vector
      raw = input.strip
      raise ParseError.new("empty vector string") if raw.empty?

      if md = PREFIX_RE.match(raw)
        case md[1]
        when "1.0"
          # Some tools emit a CVSS:1.0/ prefix for symmetry with v3+;
          # V1::Vector.parse strips it itself.
          V1::Vector.parse(raw)
        when "2.0"
          # Some tools emit a CVSS:2.0/ prefix for symmetry with v3+;
          # V2::Vector.parse strips it itself.
          V2::Vector.parse(raw)
        when "3.0", "3.1"
          V3::Vector.parse(raw)
        when "4.0"
          V4::Vector.parse(raw)
        else
          raise UnknownVersionError.new("unsupported CVSS version: #{md[1]}")
        end
      elsif v1?(raw)
        V1::Vector.parse(raw)
      else
        # No prefix, no v1 marker → assume CVSS v2.0
        V2::Vector.parse(raw)
      end
    end

    # CVSS v1.0's (NVD-defined) notation wraps the metric list in
    # parentheses: `(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)`. A single parenthesis
    # counts as a marker too, so a truncated v1 vector gets v1's
    # "unbalanced parentheses" error rather than a confusing v2 one.
    private def v1?(raw : String) : Bool
      raw.starts_with?('(') || raw.ends_with?(')') ||
        V1_IMPACT_BIAS_RE.matches?(raw)
    end
  end
end
