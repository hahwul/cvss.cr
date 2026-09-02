module CVSS
  # Top-level dispatcher that routes a vector string to the right
  # version-specific parser by inspecting the `CVSS:x.y/` prefix.
  module Parser
    extend self

    # CVSS v1.0 and v2.0 have no prefix; v3.0/v3.1/v4.0 all use a
    # `CVSS:x.y/` prefix.
    PREFIX_RE = /\ACVSS:(\d+\.\d+)\//

    # Impact Bias is a v1.0-only metric — no later version defines a `B`
    # key — so its presence is what tells a v1 vector apart from a v2.0
    # one. Matched at a segment boundary (start of string, a `/`, or the
    # `(` that opens NVD's parenthesised notation) so a key merely *ending*
    # in `B` cannot stand in for it.
    V1_IMPACT_BIAS_RE = /(?:\A|[\/(])B:/

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

    # Impact Bias is the only reliable v1 marker. The parentheses that wrap
    # NVD's v1 notation — `(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)` — cannot stand
    # in for it, because NVD's v2.0 calculator renders v2 vectors the same
    # way (`(AV:N/AC:L/Au:N/C:P/I:P/A:P)`) and those are far more common.
    # `B` is mandatory in v1 and defined by no later version, so keying off
    # it alone leaves the two notations unambiguous; both parsers strip
    # their own parentheses.
    private def v1?(raw : String) : Bool
      V1_IMPACT_BIAS_RE.matches?(raw)
    end
  end
end
