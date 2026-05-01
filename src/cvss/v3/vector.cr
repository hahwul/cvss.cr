require "./score"

module CVSS::V3
  # CVSS v3.x vector. Handles both v3.0 and v3.1 — they share metric
  # definitions and only differ in the RoundUp algorithm and the modified
  # impact formula.
  #
  # ```
  # vec = CVSS::V3::Vector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
  # vec.base_score # => 9.8
  # vec.severity   # => CVSS::Severity::Critical
  # ```
  class Vector < CVSS::Vector
    SUPPORTED_VERSIONS = {"3.0", "3.1"}

    # Canonical metric ordering used by `to_s`. Matches the FIRST calculator.
    METRIC_ORDER = %w[
      AV AC PR UI S C I A
      E RL RC
      CR IR AR MAV MAC MPR MUI MS MC MI MA
    ]

    # The eight required base metrics. A `parse` failure if any is missing.
    BASE_REQUIRED = %w[AV AC PR UI S C I A]

    getter version : String

    getter av : AttackVector
    getter ac : AttackComplexity
    getter pr : PrivilegesRequired
    getter ui : UserInteraction
    getter s : Scope
    getter c : Impact
    getter i : Impact
    getter a : Impact

    getter e : ExploitCodeMaturity?
    getter rl : RemediationLevel?
    getter rc : ReportConfidence?

    getter cr : SecurityRequirement?
    getter ir : SecurityRequirement?
    getter ar : SecurityRequirement?
    getter mav : ModifiedAttackVector?
    getter mac : ModifiedAttackComplexity?
    getter mpr : ModifiedPrivilegesRequired?
    getter mui : ModifiedUserInteraction?
    getter ms : ModifiedScope?
    getter mc : ModifiedImpact?
    getter mi : ModifiedImpact?
    getter ma : ModifiedImpact?

    def initialize(
      @av : AttackVector,
      @ac : AttackComplexity,
      @pr : PrivilegesRequired,
      @ui : UserInteraction,
      @s : Scope,
      @c : Impact,
      @i : Impact,
      @a : Impact,
      @version : String = "3.1",
      @e : ExploitCodeMaturity? = nil,
      @rl : RemediationLevel? = nil,
      @rc : ReportConfidence? = nil,
      @cr : SecurityRequirement? = nil,
      @ir : SecurityRequirement? = nil,
      @ar : SecurityRequirement? = nil,
      @mav : ModifiedAttackVector? = nil,
      @mac : ModifiedAttackComplexity? = nil,
      @mpr : ModifiedPrivilegesRequired? = nil,
      @mui : ModifiedUserInteraction? = nil,
      @ms : ModifiedScope? = nil,
      @mc : ModifiedImpact? = nil,
      @mi : ModifiedImpact? = nil,
      @ma : ModifiedImpact? = nil,
    )
      unless SUPPORTED_VERSIONS.includes?(@version)
        raise CVSS::Error.new("unsupported v3 version: #{@version}")
      end
    end

    # Non-raising parse — returns nil if the input is malformed.
    def self.parse?(input : String) : Vector?
      parse(input)
    rescue CVSS::Error
      nil
    end

    def self.parse(input : String) : Vector
      raw = input.strip
      unless raw.starts_with?("CVSS:")
        raise ParseError.new("CVSS v3 vector must start with 'CVSS:'")
      end

      head, _, body = raw[5..].partition('/')
      unless SUPPORTED_VERSIONS.includes?(head)
        raise ParseError.new("expected CVSS:3.0 or CVSS:3.1 prefix, got CVSS:#{head}")
      end
      raise ParseError.new("missing metrics after prefix") if body.empty?

      pairs = VectorString.split_metrics(body)
      seen = Set(String).new

      av : AttackVector? = nil
      ac : AttackComplexity? = nil
      pr : PrivilegesRequired? = nil
      ui : UserInteraction? = nil
      s : Scope? = nil
      c : Impact? = nil
      i : Impact? = nil
      a : Impact? = nil

      e : ExploitCodeMaturity? = nil
      rl : RemediationLevel? = nil
      rc : ReportConfidence? = nil

      cr : SecurityRequirement? = nil
      ir : SecurityRequirement? = nil
      ar : SecurityRequirement? = nil
      mav : ModifiedAttackVector? = nil
      mac : ModifiedAttackComplexity? = nil
      mpr : ModifiedPrivilegesRequired? = nil
      mui : ModifiedUserInteraction? = nil
      ms : ModifiedScope? = nil
      mc : ModifiedImpact? = nil
      mi : ModifiedImpact? = nil
      ma : ModifiedImpact? = nil

      pairs.each do |key, value|
        if seen.includes?(key)
          raise ParseError.new("duplicate metric '#{key}'")
        end
        seen << key

        case key
        when "AV"  then av = AttackVector.parse(value)
        when "AC"  then ac = AttackComplexity.parse(value)
        when "PR"  then pr = PrivilegesRequired.parse(value)
        when "UI"  then ui = UserInteraction.parse(value)
        when "S"   then s = Scope.parse(value)
        when "C"   then c = Impact.parse(value)
        when "I"   then i = Impact.parse(value)
        when "A"   then a = Impact.parse(value)
        when "E"   then e = ExploitCodeMaturity.parse(value)
        when "RL"  then rl = RemediationLevel.parse(value)
        when "RC"  then rc = ReportConfidence.parse(value)
        when "CR"  then cr = SecurityRequirement.parse(value)
        when "IR"  then ir = SecurityRequirement.parse(value)
        when "AR"  then ar = SecurityRequirement.parse(value)
        when "MAV" then mav = ModifiedAttackVector.parse(value)
        when "MAC" then mac = ModifiedAttackComplexity.parse(value)
        when "MPR" then mpr = ModifiedPrivilegesRequired.parse(value)
        when "MUI" then mui = ModifiedUserInteraction.parse(value)
        when "MS"  then ms = ModifiedScope.parse(value)
        when "MC"  then mc = ModifiedImpact.parse(value)
        when "MI"  then mi = ModifiedImpact.parse(value)
        when "MA"  then ma = ModifiedImpact.parse(value)
        else            raise ParseError.new("unknown CVSS v3 metric '#{key}'")
        end
      end

      missing = BASE_REQUIRED.reject { |k| seen.includes?(k) }
      unless missing.empty?
        raise ParseError.new("missing required base metric(s): #{missing.join(", ")}")
      end

      new(
        av: av.not_nil!, ac: ac.not_nil!, pr: pr.not_nil!, ui: ui.not_nil!,
        s: s.not_nil!, c: c.not_nil!, i: i.not_nil!, a: a.not_nil!,
        version: head,
        e: e, rl: rl, rc: rc,
        cr: cr, ir: ir, ar: ar,
        mav: mav, mac: mac, mpr: mpr, mui: mui, ms: ms,
        mc: mc, mi: mi, ma: ma,
      )
    end

    def_equals_and_hash @version,
      @av, @ac, @pr, @ui, @s, @c, @i, @a,
      @e, @rl, @rc,
      @cr, @ir, @ar, @mav, @mac, @mpr, @mui, @ms, @mc, @mi, @ma

    # Returns the stored short-code for a metric. Optional metrics that have
    # not been set return `"X"` (the v3 NotDefined code). Raises
    # `CVSS::Error` if `name` is not a recognised v3 metric key.
    def metric_value(name : String) : String
      case name
      when "AV"  then @av.code
      when "AC"  then @ac.code
      when "PR"  then @pr.code
      when "UI"  then @ui.code
      when "S"   then @s.code
      when "C"   then @c.code
      when "I"   then @i.code
      when "A"   then @a.code
      when "E"   then @e.try(&.code) || "X"
      when "RL"  then @rl.try(&.code) || "X"
      when "RC"  then @rc.try(&.code) || "X"
      when "CR"  then @cr.try(&.code) || "X"
      when "IR"  then @ir.try(&.code) || "X"
      when "AR"  then @ar.try(&.code) || "X"
      when "MAV" then @mav.try(&.code) || "X"
      when "MAC" then @mac.try(&.code) || "X"
      when "MPR" then @mpr.try(&.code) || "X"
      when "MUI" then @mui.try(&.code) || "X"
      when "MS"  then @ms.try(&.code) || "X"
      when "MC"  then @mc.try(&.code) || "X"
      when "MI"  then @mi.try(&.code) || "X"
      when "MA"  then @ma.try(&.code) || "X"
      else            raise CVSS::Error.new("unknown CVSS v3 metric '#{name}'")
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

    def physical? : Bool
      @av.physical?
    end

    def requires_privileges? : Bool
      !@pr.none?
    end

    def requires_user_interaction? : Bool
      @ui.required?
    end

    def scope_changed? : Bool
      @s.changed?
    end

    def scope_unchanged? : Bool
      @s.unchanged?
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
      h["PR"] = @pr.code
      h["UI"] = @ui.code
      h["S"] = @s.code
      h["C"] = @c.code
      h["I"] = @i.code
      h["A"] = @a.code
      h["E"] = @e.not_nil!.code if @e
      h["RL"] = @rl.not_nil!.code if @rl
      h["RC"] = @rc.not_nil!.code if @rc
      h["CR"] = @cr.not_nil!.code if @cr
      h["IR"] = @ir.not_nil!.code if @ir
      h["AR"] = @ar.not_nil!.code if @ar
      h["MAV"] = @mav.not_nil!.code if @mav
      h["MAC"] = @mac.not_nil!.code if @mac
      h["MPR"] = @mpr.not_nil!.code if @mpr
      h["MUI"] = @mui.not_nil!.code if @mui
      h["MS"] = @ms.not_nil!.code if @ms
      h["MC"] = @mc.not_nil!.code if @mc
      h["MI"] = @mi.not_nil!.code if @mi
      h["MA"] = @ma.not_nil!.code if @ma
      h
    end

    # ───── Public API ─────

    def base_score : Float64
      Score.base_score(self)
    end

    def temporal_score : Float64
      Score.temporal_score(self)
    end

    def environmental_score : Float64
      Score.environmental_score(self)
    end

    # ───── Sub-scores (debugging / tooling helpers) ─────

    # Impact Sub-Score (ISS) before scope-aware scaling — see CVSS v3.1 §7.1.
    def iss : Float64
      Score.iss(self)
    end

    # Impact subscore (after Scope-aware scaling).
    def impact_subscore : Float64
      Score.impact(self)
    end

    # Exploitability subscore.
    def exploitability_subscore : Float64
      Score.exploitability(self)
    end

    def severity : Severity
      Severity.from_score(base_score)
    end

    def temporal_severity : Severity
      Severity.from_score(temporal_score)
    end

    def environmental_severity : Severity
      Severity.from_score(environmental_score)
    end

    def to_s(io : IO) : Nil
      io << "CVSS:" << @version
      METRIC_ORDER.each do |key|
        case key
        when "AV"  then write_metric(io, key, @av.code)
        when "AC"  then write_metric(io, key, @ac.code)
        when "PR"  then write_metric(io, key, @pr.code)
        when "UI"  then write_metric(io, key, @ui.code)
        when "S"   then write_metric(io, key, @s.code)
        when "C"   then write_metric(io, key, @c.code)
        when "I"   then write_metric(io, key, @i.code)
        when "A"   then write_metric(io, key, @a.code)
        when "E"   then write_optional(io, key, @e)
        when "RL"  then write_optional(io, key, @rl)
        when "RC"  then write_optional(io, key, @rc)
        when "CR"  then write_optional(io, key, @cr)
        when "IR"  then write_optional(io, key, @ir)
        when "AR"  then write_optional(io, key, @ar)
        when "MAV" then write_optional(io, key, @mav)
        when "MAC" then write_optional(io, key, @mac)
        when "MPR" then write_optional(io, key, @mpr)
        when "MUI" then write_optional(io, key, @mui)
        when "MS"  then write_optional(io, key, @ms)
        when "MC"  then write_optional(io, key, @mc)
        when "MI"  then write_optional(io, key, @mi)
        when "MA"  then write_optional(io, key, @ma)
        end
      end
    end

    private def write_metric(io : IO, key : String, code : String) : Nil
      io << '/' << key << ':' << code
    end

    private def write_optional(io : IO, key : String, metric) : Nil
      return if metric.nil?
      write_metric(io, key, metric.code)
    end
  end
end
