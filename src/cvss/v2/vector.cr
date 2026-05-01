require "./score"

module CVSS::V2
  # CVSS v2.0 vector. Format has no `CVSS:x.y/` prefix:
  #   "AV:N/AC:L/Au:N/C:P/I:P/A:P"
  class Vector < CVSS::Vector
    # Canonical metric ordering used by `to_s`. v2.0 has no `CVSS:x.y/`
    # prefix, so the first emitted metric appears with no leading separator.
    METRIC_ORDER = %w[
      AV AC Au C I A
      E RL RC
      CDP TD CR IR AR
    ]

    # The six required base metrics — `parse` fails if any is missing.
    BASE_REQUIRED = %w[AV AC Au C I A]

    getter av : AccessVector
    getter ac : AccessComplexity
    getter au : Authentication
    getter c : Impact
    getter i : Impact
    getter a : Impact

    getter e : Exploitability?
    getter rl : RemediationLevel?
    getter rc : ReportConfidence?

    getter cdp : CollateralDamagePotential?
    getter td : TargetDistribution?
    getter cr : SecurityRequirement?
    getter ir : SecurityRequirement?
    getter ar : SecurityRequirement?

    def version : String
      "2.0"
    end

    def initialize(
      @av : AccessVector,
      @ac : AccessComplexity,
      @au : Authentication,
      @c : Impact,
      @i : Impact,
      @a : Impact,
      @e : Exploitability? = nil,
      @rl : RemediationLevel? = nil,
      @rc : ReportConfidence? = nil,
      @cdp : CollateralDamagePotential? = nil,
      @td : TargetDistribution? = nil,
      @cr : SecurityRequirement? = nil,
      @ir : SecurityRequirement? = nil,
      @ar : SecurityRequirement? = nil,
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
      raise ParseError.new("empty CVSS v2 vector") if raw.empty?

      # Tolerate an explicit "CVSS:2.0/" prefix even though it isn't part
      # of the v2 spec — some tools emit it for symmetry with v3+.
      body = raw.starts_with?("CVSS:2.0/") ? raw[("CVSS:2.0/".size)..] : raw

      pairs = VectorString.split_metrics(body)
      seen = Set(String).new

      av : AccessVector? = nil
      ac : AccessComplexity? = nil
      au : Authentication? = nil
      c : Impact? = nil
      i : Impact? = nil
      a : Impact? = nil

      e : Exploitability? = nil
      rl : RemediationLevel? = nil
      rc : ReportConfidence? = nil

      cdp : CollateralDamagePotential? = nil
      td : TargetDistribution? = nil
      cr : SecurityRequirement? = nil
      ir : SecurityRequirement? = nil
      ar : SecurityRequirement? = nil

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
        when "E"   then e = Exploitability.parse(value)
        when "RL"  then rl = RemediationLevel.parse(value)
        when "RC"  then rc = ReportConfidence.parse(value)
        when "CDP" then cdp = CollateralDamagePotential.parse(value)
        when "TD"  then td = TargetDistribution.parse(value)
        when "CR"  then cr = SecurityRequirement.parse(value)
        when "IR"  then ir = SecurityRequirement.parse(value)
        when "AR"  then ar = SecurityRequirement.parse(value)
        else            raise ParseError.new("unknown CVSS v2 metric '#{key}'")
        end
      end

      missing = BASE_REQUIRED.reject { |k| seen.includes?(k) }
      unless missing.empty?
        raise ParseError.new("missing required base metric(s): #{missing.join(", ")}")
      end

      new(
        av: av.not_nil!, ac: ac.not_nil!, au: au.not_nil!,
        c: c.not_nil!, i: i.not_nil!, a: a.not_nil!,
        e: e, rl: rl, rc: rc,
        cdp: cdp, td: td, cr: cr, ir: ir, ar: ar,
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
      Severity.from_v2_score(base_score)
    end

    def temporal_severity : Severity
      Severity.from_v2_score(temporal_score)
    end

    def environmental_severity : Severity
      Severity.from_v2_score(environmental_score)
    end

    def_equals_and_hash @av, @ac, @au, @c, @i, @a,
      @e, @rl, @rc, @cdp, @td, @cr, @ir, @ar

    # Returns the stored short-code for a metric. Optional metrics that have
    # not been set return `"ND"` (the v2 NotDefined code). Raises
    # `CVSS::Error` if `name` is not a recognised v2 metric key.
    def metric_value(name : String) : String
      case name
      when "AV"  then @av.code
      when "AC"  then @ac.code
      when "Au"  then @au.code
      when "C"   then @c.code
      when "I"   then @i.code
      when "A"   then @a.code
      when "E"   then @e.try(&.code) || "ND"
      when "RL"  then @rl.try(&.code) || "ND"
      when "RC"  then @rc.try(&.code) || "ND"
      when "CDP" then @cdp.try(&.code) || "ND"
      when "TD"  then @td.try(&.code) || "ND"
      when "CR"  then @cr.try(&.code) || "ND"
      when "IR"  then @ir.try(&.code) || "ND"
      when "AR"  then @ar.try(&.code) || "ND"
      else            raise CVSS::Error.new("unknown CVSS v2 metric '#{name}'")
      end
    end

    # ───── Classification helpers ─────

    def network? : Bool
      @av.network?
    end

    def adjacent_network? : Bool
      @av.adjacent_network?
    end

    def local? : Bool
      @av.local?
    end

    def requires_authentication? : Bool
      !@au.none?
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
      h["E"] = @e.not_nil!.code if @e
      h["RL"] = @rl.not_nil!.code if @rl
      h["RC"] = @rc.not_nil!.code if @rc
      h["CDP"] = @cdp.not_nil!.code if @cdp
      h["TD"] = @td.not_nil!.code if @td
      h["CR"] = @cr.not_nil!.code if @cr
      h["IR"] = @ir.not_nil!.code if @ir
      h["AR"] = @ar.not_nil!.code if @ar
      h
    end

    def to_s(io : IO) : Nil
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
          when "E"   then @e.try(&.code)
          when "RL"  then @rl.try(&.code)
          when "RC"  then @rc.try(&.code)
          when "CDP" then @cdp.try(&.code)
          when "TD"  then @td.try(&.code)
          when "CR"  then @cr.try(&.code)
          when "IR"  then @ir.try(&.code)
          when "AR"  then @ar.try(&.code)
          end
        next if code.nil?
        io << '/' if emitted
        emitted = true
        io << key << ':' << code
      end
    end
  end
end
