module CVSS
  # Top-level dispatcher that routes a vector string to the right
  # version-specific parser by inspecting the `CVSS:x.y/` prefix.
  module Parser
    extend self

    # Impact Bias is a v1.0-only metric — no later version defines a `B`
    # key — so its presence is what tells a v1 vector apart from a v2.0
    # one. Matched at a segment boundary (start of string, a `/`, or the
    # `(` that opens NVD's parenthesised notation) so a key merely *ending*
    # in `B` cannot stand in for it.
    V1_IMPACT_BIAS_RE = /(?:\A|[\/(])B:/

    # Metric keys no v1.0 or v2.0 vector can carry. A prefix-less string
    # holding one of these is a v3.x or v4.0 vector that lost its mandatory
    # `CVSS:x.y/` prefix — worth saying so, because falling through to the
    # v2 parser reports it as an unknown v2 metric instead.
    #
    # v4.0 is tested first: a v4 vector also carries `PR`/`UI`, which the
    # v3 pattern matches.
    V4_ONLY_RE = /(?:\A|[\/(])(?:AT|VC|VI|VA|SC|SI|SA|MAT|MVC|MVI|MVA|MSC|MSI|MSA|RE):/
    V3_ONLY_RE = /(?:\A|[\/(])(?:PR|UI|S|MAV|MAC|MPR|MUI|MS|MC|MI|MA):/

    def parse(input : String) : Vector
      raw = input.strip
      raise ParseError.new("empty vector string") if raw.empty?

      if version = VectorString.prefix_version(raw)
        case version
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
          raise UnknownVersionError.new("unsupported CVSS version: #{version}")
        end
      elsif v1?(raw)
        V1::Vector.parse(raw)
      else
        reject_unprefixed_v3_or_v4(raw)
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

    # The `CVSS:x.y/` prefix is mandatory from v3.0 onward, and for v3.x it
    # is also the only thing that separates v3.0 from v3.1 — the metric sets
    # are identical, but the RoundUp and modified-impact formulas are not.
    # So a prefix-less v3/v4 vector is reported rather than guessed at.
    private def reject_unprefixed_v3_or_v4(raw : String) : Nil
      if V4_ONLY_RE.matches?(raw)
        raise ParseError.new(
          "vector carries CVSS v4.0 metrics but no 'CVSS:4.0/' prefix; " \
          "the prefix is mandatory from CVSS v3.0 onward")
      end
      if V3_ONLY_RE.matches?(raw)
        raise ParseError.new(
          "vector carries CVSS v3.x metrics but no 'CVSS:3.0/' or 'CVSS:3.1/' " \
          "prefix; the prefix is mandatory from CVSS v3.0 onward, and is the " \
          "only thing that distinguishes v3.0 from v3.1")
      end
    end
  end
end
