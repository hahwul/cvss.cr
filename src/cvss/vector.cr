module CVSS
  # Largest magnitude whose five-decimal integer snap still fits in an
  # `Int64` (`Int64::MAX` is ~9.2233e18, so the snap tops out just above
  # 9.2233e13); rounded down for headroom.
  ROUND1_SNAP_LIMIT = 9.0e13

  # Round `x` to one decimal place. Ties break *upwards*, i.e. toward
  # positive infinity rather than away from zero — `round1(0.15)` is `0.2`
  # and `round1(-0.15)` is `-0.1`. CVSS scores are non-negative, so only the
  # positive half is ever exercised. Used by the v2 score formulas
  # (`round_to_1_decimal` in the CVSS v2 guide) and by the JSON serialiser
  # for the v3 exploitability/impact sub-scores. Centralised here so the
  # score module and the JSON serialiser cannot drift apart.
  #
  # The value is first snapped to five decimal places in integer space. A
  # naive `(x * 10 + 0.5).floor` reads `3.0 * 0.95` as 2.8499999999999996
  # and rounds it down to 2.8, where the arithmetic the spec describes gives
  # 2.85 → 2.9. This is the same binary-representation trap CVSS v3.1 §7.1
  # (and its Appendix A) works around in `Roundup`.
  def self.round1(x : Float64) : Float64
    # NaN and ±Infinity have no one-decimal form to snap to, and every input
    # past `ROUND1_SNAP_LIMIT` would overflow `to_i64`. Scoring never reaches
    # either, but `round1` is public, so degrade instead of letting a raw
    # `OverflowError` escape. Above the limit a Float64 carries no fractional
    # part anyway, which is all the snap exists to correct.
    return x if x.nan? || x.infinite?
    return ((x * 10.0 + 0.5).floor) / 10.0 if x.abs >= ROUND1_SNAP_LIMIT

    scaled = (x * 100_000.0).round.to_i64
    ((scaled + 5_000) // 10_000).to_f / 10.0
  end

  # Common interface for every CVSS vector implementation.
  #
  # Each version (V2, V3, V4) implements its own subclass of this abstract
  # base. The shared API lets callers treat any parsed vector uniformly:
  #
  # ```
  # vec = CVSS.parse(input)
  # vec.base_score # => Float64
  # vec.severity   # => CVSS::Severity
  # vec.version    # => "3.1"
  # vec.to_s       # => canonical vector string
  # ```
  #
  # Vectors are `Comparable` by `base_score` — sort/compare across versions
  # by severity:
  #
  # ```
  # vulns = inputs.map { |s| CVSS.parse(s) }
  # vulns.sort.last # most severe
  # vulns.min       # least severe
  # ```
  #
  # Equality is *structural* and class-aware: two vectors are `==` only when
  # they are the same concrete class with identical metric values. A v3 and
  # v4 vector that happen to share a `base_score` are not `==`.
  abstract class Vector
    include Comparable(Vector)

    abstract def version : String
    abstract def base_score : Float64
    abstract def severity : Severity
    abstract def to_s(io : IO) : Nil

    # Every metric key this version defines, in the order the FIRST
    # calculator emits them. Drives both `to_h` and `to_s`.
    abstract def metric_order : Array(String)

    # The short-code stored for `name`, or `nil` when `name` is an optional
    # metric this vector does not carry. Raises `CVSS::Error` for a key the
    # version does not define.
    #
    # This is the single source of truth for a vector's metric values:
    # `metric_value`, `to_h` and `to_s` are all derived from it, so the three
    # cannot drift apart.
    #
    # ```
    # vec = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    # vec.metric_code?("AV") # => "N"
    # vec.metric_code?("E")  # => nil
    # ```
    abstract def metric_code?(name : String) : String?

    # The code an unset optional metric reports from `metric_value` —
    # `"X"` from CVSS v3.0 onward, `"ND"` in the v1.0 / v2.0 notation.
    protected abstract def not_defined_code : String

    # Returns the short-code stored for a metric. Optional metrics that have
    # not been set report this version's "not defined" code rather than
    # `nil`; use `metric_code?` to tell the two apart. Raises `CVSS::Error`
    # if `name` is not a metric key this version defines.
    #
    # ```
    # vec = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    # vec.metric_value("AV") # => "N"
    # vec.metric_value("E")  # => "X"
    # ```
    def metric_value(name : String) : String
      metric_code?(name) || not_defined_code
    end

    # Returns a `Hash(String, String)` of metric short-codes, in canonical
    # order. Optional metrics are only included when set.
    #
    # ```
    # CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F").to_h
    # # => {"AV" => "N", ..., "A" => "H", "E" => "F"}
    # ```
    def to_h : Hash(String, String)
      metric_order.each_with_object({} of String => String) do |key, hash|
        if code = metric_code?(key)
          hash[key] = code
        end
      end
    end

    # Writes every set metric as `/KEY:CODE`, in canonical order.
    #
    # `separator_before_first` says whether the first metric needs its own
    # leading `/`: true once a `CVSS:x.y` prefix has been written (v3.x,
    # v4.0), false for the bare v1.0 / v2.0 notation where the first metric
    # opens the string.
    protected def write_metrics(io : IO, separator_before_first : Bool) : Nil
      need_separator = separator_before_first
      metric_order.each do |key|
        code = metric_code?(key)
        next if code.nil?
        io << '/' if need_separator
        need_separator = true
        io << key << ':' << code
      end
    end

    # Order vectors by their base score. Subclasses do not need to override.
    # Returns nil only if a score is NaN, which never happens for valid
    # CVSS inputs — included for `Float64#<=>` compatibility.
    def <=>(other : Vector) : Int32?
      base_score <=> other.base_score
    end

    # Default cross-class equality: vectors of different concrete classes are
    # never `==`. Same-class subclasses override with field-level equality.
    # This also overrides the `==` that `Comparable` would otherwise derive
    # from `<=>` (we don't want score-equal vectors to compare equal).
    def ==(other : Vector) : Bool
      false
    end

    def to_s : String
      String.build { |io| to_s(io) }
    end

    def inspect(io : IO) : Nil
      io << "#<" << self.class.name << " "
      to_s(io)
      io << " base=" << base_score
      io << ">"
    end
  end

  # Shape-level handling of a raw vector string, shared by every version's
  # parser: unwrapping NVD's parentheses (`strip_parens`), and splitting the
  # remaining body into an ordered array of `{key, value}` tuples while
  # validating its shape (`split_metrics`). Neither knows what any metric
  # means — that is each version's job.
  module VectorString
    extend self

    # The `CVSS:x.y/` prefix that opens every vector string from CVSS v3.0
    # onward, and that some tools also put in front of v1.0 / v2.0 vectors.
    #
    # Matched case-insensitively. The specs spell the prefix `CVSS:`, but
    # lower- and mixed-case spellings turn up in real feeds and in
    # hand-written data. The prefix is a fixed literal, not a metric value,
    # so accepting any spelling of it introduces no ambiguity — metric keys
    # and values stay case-sensitive, as the specs require.
    PREFIX_RE = /\ACVSS:(\d+\.\d+)\//i

    # The CVSS version declared by a `CVSS:x.y/` prefix, or nil when the
    # string carries none.
    def prefix_version(body : String) : String?
      PREFIX_RE.match(body).try(&.[1])
    end

    # Removes a `CVSS:x.y/` prefix declaring one of `expected`.
    #
    # A string with no prefix at all is returned unchanged — v1.0 and v2.0
    # are normally written without one — while a prefix naming a different
    # version is an error, so that `V2::Vector.parse` on a v3 string says so
    # rather than reporting `CVSS` as an unknown metric key.
    def strip_prefix(body : String, expected : Enumerable(String)) : String
      md = PREFIX_RE.match(body)
      return body if md.nil?

      version = md[1]
      unless expected.includes?(version)
        wanted = expected.map { |v| "CVSS:#{v}" }.join(" or ")
        raise ParseError.new("expected #{wanted} prefix, got CVSS:#{version}")
      end
      body[md[0].size..]
    end

    def split_metrics(body : String) : Array({String, String})
      raise ParseError.new("empty vector body") if body.empty?

      pairs = [] of {String, String}
      body.split('/').each do |segment|
        raise ParseError.new("empty metric segment") if segment.empty?
        key, _, value = segment.partition(':')
        if value.empty? || key.empty? || !segment.includes?(':')
          raise ParseError.new("malformed metric segment '#{segment}'")
        end
        pairs << {key, value}
      end
      pairs
    end

    # Removes the parentheses that wrap NVD's vector notation — mandatory
    # for CVSS v1.0, and how NVD's v2.0 calculator still renders a v2
    # vector (`.../v2-calculator?vector=(AV:N/AC:L/…)`). Both halves must
    # be present: a lone "(" or ")" is malformed, not tolerable.
    #
    # The error names no CVSS version deliberately. A vector truncated
    # mid-string has lost whatever marker `Parser` dispatches on — for v1
    # that marker is `B`, which lives at the tail — so whichever parser
    # ends up here is only guessing at the version, while "the parentheses
    # do not match" is true of the input either way.
    def strip_parens(body : String) : String
      return body unless body.starts_with?('(') || body.ends_with?(')')
      unless body.starts_with?('(') && body.ends_with?(')')
        raise ParseError.new("unbalanced parentheses in vector string")
      end
      body[1...-1]
    end
  end
end
