module CVSS
  # Top-level dispatcher that routes a vector string to the right
  # version-specific parser by inspecting the `CVSS:x.y/` prefix.
  module Parser
    extend self

    # CVSS v2.0 has no prefix; v3.0/v3.1/v4.0 all use a `CVSS:x.y/` prefix.
    PREFIX_RE = /\ACVSS:(\d+\.\d+)\//

    def parse(input : String) : Vector
      raw = input.strip
      raise ParseError.new("empty vector string") if raw.empty?

      if md = PREFIX_RE.match(raw)
        case md[1]
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
      else
        # No prefix → assume CVSS v2.0
        V2::Vector.parse(raw)
      end
    end
  end
end
