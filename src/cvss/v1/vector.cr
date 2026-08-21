require "./score"

module CVSS::V1
  # CVSS v1.0 vector.
  #
  # The v1.0 guide never standardised a vector string; the notation below
  # is NVD's, which every v1-era publisher adopted and which NVD documented
  # at `nvd.nist.gov/cvss.cfm?vectorinfo`:
  #
  #     (AV:[R,L]/AC:[H,L]/Au:[R,NR]/C:[N,P,C]/I:[N,P,C]/A:[N,P,C]/B:[N,C,I,A])
  #
  # with temporal metrics appended inside the same parentheses:
  #
  #     /E:[U,P,F,H]/RL:[O,T,W,U]/RC:[U,Uc,C]
  #
  # ```
  # vec = CVSS::V1::Vector.parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)")
  # vec.base_score # => 10.0
  # vec.severity   # => CVSS::Severity::High
  # ```
  #
  # NVD never published a vector form for the environmental group, so
  # `CDP` and `TD` are accepted and emitted using the same short codes
  # CVSS v2.0 later gave them. That is an extension, not a v1.0 quirk —
  # vectors that omit them round-trip byte-for-byte either way.
  class Vector < CVSS::Vector
    # Canonical metric ordering used by `to_s`.
    METRIC_ORDER = %w[
      AV AC Au C I A B
      E RL RC
      CDP TD
    ]

    # The seven required base metrics — `parse` fails if any is missing.
    BASE_REQUIRED = %w[AV AC Au C I A B]

    getter av : AccessVector
    getter ac : AccessComplexity
    getter au : Authentication
    getter c : Impact
    getter i : Impact
    getter a : Impact
    getter b : ImpactBias

    getter e : Exploitability?
    getter rl : RemediationLevel?
    getter rc : ReportConfidence?

    getter cdp : CollateralDamagePotential?
    getter td : TargetDistribution?

    def version : String
      "1.0"
    end

    def initialize(
      @av : AccessVector,
      @ac : AccessComplexity,
      @au : Authentication,
      @c : Impact,
      @i : Impact,
      @a : Impact,
      @b : ImpactBias,
      @e : Exploitability? = nil,
      @rl : RemediationLevel? = nil,
      @rc : ReportConfidence? = nil,
      @cdp : CollateralDamagePotential? = nil,
      @td : TargetDistribution? = nil,
    )
    end

    # Non-raising parse — returns nil if the input is malformed.
    def self.parse?(input : String) : Vector?
      parse(input)
    rescue CVSS::Error
      nil
    end

    def self.parse(input : String) : Vector
      raw = input.strip
      raise ParseError.new("empty CVSS v1 vector") if raw.empty?

      body = raw

      # Tolerate an explicit "CVSS:1.0/" prefix even though it isn't part
      # of any v1-era notation — it keeps `CVSS.parse` symmetric with v3+.
      body = body[("CVSS:1.0/".size)..] if body.starts_with?("CVSS:1.0/")

      # The NVD notation wraps the metric list in parentheses. Both halves
      # must be present: a lone "(" or ")" is malformed, not tolerable.
      if body.starts_with?('(') || body.ends_with?(')')
        unless body.starts_with?('(') && body.ends_with?(')')
          raise ParseError.new("unbalanced parentheses in CVSS v1 vector")
        end
        body = body[1...-1]
      end

      pairs = VectorString.split_metrics(body)
      seen = Set(String).new

      av : AccessVector? = nil
      ac : AccessComplexity? = nil
      au : Authentication? = nil
      c : Impact? = nil
      i : Impact? = nil
      a : Impact? = nil
      b : ImpactBias? = nil

      e : Exploitability? = nil
      rl : RemediationLevel? = nil
      rc : ReportConfidence? = nil

      cdp : CollateralDamagePotential? = nil
      td : TargetDistribution? = nil

      pairs.each do |key, value|
        if seen.includes?(key)
          raise ParseError.new("duplicate metric '#{key}'")
        end
        seen << key

        case key
        when "AV"  then av = AccessVector.parse(value)
        when "AC"  then ac = AccessComplexity.parse(value)
        when "Au"  then au = Authentication.parse(value)
        when "C"   then c = Impact.parse(value)
        when "I"   then i = Impact.parse(value)
        when "A"   then a = Impact.parse(value)
        when "B"   then b = ImpactBias.parse(value)
        when "E"   then e = Exploitability.parse(value)
        when "RL"  then rl = RemediationLevel.parse(value)
        when "RC"  then rc = ReportConfidence.parse(value)
        when "CDP" then cdp = CollateralDamagePotential.parse(value)
        when "TD"  then td = TargetDistribution.parse(value)
        else            raise ParseError.new("unknown CVSS v1 metric '#{key}'")
        end
      end

      missing = BASE_REQUIRED.reject { |k| seen.includes?(k) }
      unless missing.empty?
        raise ParseError.new("missing required base metric(s): #{missing.join(", ")}")
      end

      new(
        av: av.not_nil!, ac: ac.not_nil!, au: au.not_nil!,
        c: c.not_nil!, i: i.not_nil!, a: a.not_nil!, b: b.not_nil!,
        e: e, rl: rl, rc: rc,
        cdp: cdp, td: td,
      )
    end

    def base_score : Float64
      Score.base_score(self)
    end

    def temporal_score : Float64
      Score.temporal_score(self)
    end

    def environmental_score : Float64
      Score.environmental_score(self)
    end

    def severity : Severity
      Severity.from_v1_score(base_score)
    end

    def temporal_severity : Severity
      Severity.from_v1_score(temporal_score)
    end

    def environmental_severity : Severity
      Severity.from_v1_score(environmental_score)
    end

    def_equals_and_hash @av, @ac, @au, @c, @i, @a, @b,
      @e, @rl, @rc, @cdp, @td

    # Returns the stored short-code for a metric. v1.0 has no "Not Defined"
    # code of its own, so unset optional metrics report `"ND"` — the same
    # sentinel `CVSS::V2::Vector#metric_value` uses. Raises `CVSS::Error`
    # if `name` is not a recognised v1 metric key.
    def metric_value(name : String) : String
      case name
      when "AV"  then @av.code
      when "AC"  then @ac.code
      when "Au"  then @au.code
      when "C"   then @c.code
      when "I"   then @i.code
      when "A"   then @a.code
      when "B"   then @b.code
      when "E"   then @e.try(&.code) || "ND"
      when "RL"  then @rl.try(&.code) || "ND"
      when "RC"  then @rc.try(&.code) || "ND"
      when "CDP" then @cdp.try(&.code) || "ND"
      when "TD"  then @td.try(&.code) || "ND"
      else            raise CVSS::Error.new("unknown CVSS v1 metric '#{name}'")
      end
    end

    # ───── Classification helpers ─────

    def remote? : Bool
      @av.remote?
    end

    # Alias for `remote?`. v1.0's "Remote" is the metric v2.0 renamed to
    # "Network"; the alias keeps cross-version filtering uniform.
    def network? : Bool
      @av.remote?
    end

    def local? : Bool
      @av.local?
    end

    def requires_authentication? : Bool
      @au.required?
    end

    def impacts_confidentiality? : Bool
      !@c.none?
    end

    def impacts_integrity? : Bool
      !@i.none?
    end

    def impacts_availability? : Bool
      !@a.none?
    end

    # ───── Hash export ─────

    # Returns a `Hash(String, String)` of metric short-codes, in canonical
    # order. Optional metrics are only included when set.
    def to_h : Hash(String, String)
      h = {} of String => String
      h["AV"] = @av.code
      h["AC"] = @ac.code
      h["Au"] = @au.code
      h["C"] = @c.code
      h["I"] = @i.code
      h["A"] = @a.code
      h["B"] = @b.code
      h["E"] = @e.not_nil!.code if @e
      h["RL"] = @rl.not_nil!.code if @rl
      h["RC"] = @rc.not_nil!.code if @rc
      h["CDP"] = @cdp.not_nil!.code if @cdp
      h["TD"] = @td.not_nil!.code if @td
      h
    end

    # Emits the parenthesised NVD notation, e.g.
    # `(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)`.
    def to_s(io : IO) : Nil
      io << '('
      emitted = false
      METRIC_ORDER.each do |key|
        code =
          case key
          when "AV"  then @av.code
          when "AC"  then @ac.code
          when "Au"  then @au.code
          when "C"   then @c.code
          when "I"   then @i.code
          when "A"   then @a.code
          when "B"   then @b.code
          when "E"   then @e.try(&.code)
          when "RL"  then @rl.try(&.code)
          when "RC"  then @rc.try(&.code)
          when "CDP" then @cdp.try(&.code)
          when "TD"  then @td.try(&.code)
          end
        next if code.nil?
        io << '/' if emitted
        emitted = true
        io << key << ':' << code
      end
      io << ')'
    end
  end
end
