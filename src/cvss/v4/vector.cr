require "./score"

module CVSS::V4
  # Vector nomenclature classification per CVSS v4.0 specification §6.
  #
  # A v4.0 vector is labelled by which optional metric groups carry
  # meaningful (non-`X`) values:
  #
  # | Code      | Threat (E)  | Environmental (CR/IR/AR/M*) |
  # |-----------|-------------|-----------------------------|
  # | CVSS-B    | unset / X   | unset / X                   |
  # | CVSS-BT   | set         | unset / X                   |
  # | CVSS-BE   | unset / X   | set                         |
  # | CVSS-BTE  | set         | set                         |
  #
  # Supplemental metrics (S, AU, R, V, RE, U) are informational and
  # never change the nomenclature.
  enum Nomenclature
    Base                    # CVSS-B
    BaseThreat              # CVSS-BT
    BaseEnvironmental       # CVSS-BE
    BaseThreatEnvironmental # CVSS-BTE

    # Spec-defined label string ("CVSS-B", "CVSS-BT", …). Overrides the
    # default `Enum#to_s` which would otherwise return the member name.
    def to_s : String
      case self
      in Base                    then "CVSS-B"
      in BaseThreat              then "CVSS-BT"
      in BaseEnvironmental       then "CVSS-BE"
      in BaseThreatEnvironmental then "CVSS-BTE"
      end
    end

    def to_s(io : IO) : Nil
      io << to_s
    end
  end

  # CVSS v4.0 vector.
  #
  # ```
  # vec = CVSS::V4::Vector.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
  # vec.base_score # => 9.3
  # vec.severity   # => CVSS::Severity::Critical
  # ```
  class Vector < CVSS::Vector
    # Canonical metric ordering used by `to_s`. Matches the FIRST calculator.
    METRIC_ORDER = %w[
      AV AC AT PR UI VC VI VA SC SI SA
      E
      CR IR AR
      MAV MAC MAT MPR MUI MVC MVI MVA MSC MSI MSA
      S AU R V RE U
    ]

    BASE_REQUIRED = %w[AV AC AT PR UI VC VI VA SC SI SA]

    # Base
    getter av : AttackVector
    getter ac : AttackComplexity
    getter at : AttackRequirements
    getter pr : PrivilegesRequired
    getter ui : UserInteraction
    getter vc : VulnerableImpact
    getter vi : VulnerableImpact
    getter va : VulnerableImpact
    getter sc : SubsequentImpact
    getter si : SubsequentImpact
    getter sa : SubsequentImpact

    # Threat
    getter e : ExploitMaturity?

    # Environmental — Security Requirements
    getter cr : SecurityRequirement?
    getter ir : SecurityRequirement?
    getter ar : SecurityRequirement?

    # Environmental — Modified base
    getter mav : ModifiedAttackVector?
    getter mac : ModifiedAttackComplexity?
    getter mat : ModifiedAttackRequirements?
    getter mpr : ModifiedPrivilegesRequired?
    getter mui : ModifiedUserInteraction?
    getter mvc : ModifiedVulnerableImpact?
    getter mvi : ModifiedVulnerableImpact?
    getter mva : ModifiedVulnerableImpact?
    getter msc : ModifiedSubsequentConfidentiality?
    getter msi : ModifiedSubsequentIntegrity?
    getter msa : ModifiedSubsequentAvailability?

    # Supplemental (informational only)
    getter s : Safety?
    getter au : Automatable?
    getter r : Recovery?
    getter v : ValueDensity?
    getter re : ResponseEffort?
    getter u : ProviderUrgency?

    def version : String
      "4.0"
    end

    def initialize(
      @av : AttackVector,
      @ac : AttackComplexity,
      @at : AttackRequirements,
      @pr : PrivilegesRequired,
      @ui : UserInteraction,
      @vc : VulnerableImpact,
      @vi : VulnerableImpact,
      @va : VulnerableImpact,
      @sc : SubsequentImpact,
      @si : SubsequentImpact,
      @sa : SubsequentImpact,
      @e : ExploitMaturity? = nil,
      @cr : SecurityRequirement? = nil,
      @ir : SecurityRequirement? = nil,
      @ar : SecurityRequirement? = nil,
      @mav : ModifiedAttackVector? = nil,
      @mac : ModifiedAttackComplexity? = nil,
      @mat : ModifiedAttackRequirements? = nil,
      @mpr : ModifiedPrivilegesRequired? = nil,
      @mui : ModifiedUserInteraction? = nil,
      @mvc : ModifiedVulnerableImpact? = nil,
      @mvi : ModifiedVulnerableImpact? = nil,
      @mva : ModifiedVulnerableImpact? = nil,
      @msc : ModifiedSubsequentConfidentiality? = nil,
      @msi : ModifiedSubsequentIntegrity? = nil,
      @msa : ModifiedSubsequentAvailability? = nil,
      @s : Safety? = nil,
      @au : Automatable? = nil,
      @r : Recovery? = nil,
      @v : ValueDensity? = nil,
      @re : ResponseEffort? = nil,
      @u : ProviderUrgency? = nil,
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
      unless raw.starts_with?("CVSS:4.0/")
        raise ParseError.new("CVSS v4 vector must start with 'CVSS:4.0/'")
      end

      body = raw[("CVSS:4.0/".size)..]
      raise ParseError.new("missing metrics after prefix") if body.empty?

      pairs = VectorString.split_metrics(body)
      seen = Set(String).new
      values = {} of String => String

      pairs.each do |key, value|
        if seen.includes?(key)
          raise ParseError.new("duplicate metric '#{key}'")
        end
        seen << key
        values[key] = value
      end

      missing = BASE_REQUIRED.reject { |k| seen.includes?(k) }
      unless missing.empty?
        raise ParseError.new("missing required base metric(s): #{missing.join(", ")}")
      end

      unknown = values.keys.reject { |k| METRIC_ORDER.includes?(k) }
      unless unknown.empty?
        raise ParseError.new("unknown CVSS v4 metric(s): #{unknown.join(", ")}")
      end

      new(
        av: AttackVector.parse(values["AV"]),
        ac: AttackComplexity.parse(values["AC"]),
        at: AttackRequirements.parse(values["AT"]),
        pr: PrivilegesRequired.parse(values["PR"]),
        ui: UserInteraction.parse(values["UI"]),
        vc: VulnerableImpact.parse(values["VC"]),
        vi: VulnerableImpact.parse(values["VI"]),
        va: VulnerableImpact.parse(values["VA"]),
        sc: SubsequentImpact.parse(values["SC"]),
        si: SubsequentImpact.parse(values["SI"]),
        sa: SubsequentImpact.parse(values["SA"]),
        e: values["E"]?.try { |s| ExploitMaturity.parse(s) },
        cr: values["CR"]?.try { |s| SecurityRequirement.parse(s) },
        ir: values["IR"]?.try { |s| SecurityRequirement.parse(s) },
        ar: values["AR"]?.try { |s| SecurityRequirement.parse(s) },
        mav: values["MAV"]?.try { |s| ModifiedAttackVector.parse(s) },
        mac: values["MAC"]?.try { |s| ModifiedAttackComplexity.parse(s) },
        mat: values["MAT"]?.try { |s| ModifiedAttackRequirements.parse(s) },
        mpr: values["MPR"]?.try { |s| ModifiedPrivilegesRequired.parse(s) },
        mui: values["MUI"]?.try { |s| ModifiedUserInteraction.parse(s) },
        mvc: values["MVC"]?.try { |s| ModifiedVulnerableImpact.parse(s) },
        mvi: values["MVI"]?.try { |s| ModifiedVulnerableImpact.parse(s) },
        mva: values["MVA"]?.try { |s| ModifiedVulnerableImpact.parse(s) },
        msc: values["MSC"]?.try { |s| ModifiedSubsequentConfidentiality.parse(s) },
        msi: values["MSI"]?.try { |s| ModifiedSubsequentIntegrity.parse(s) },
        msa: values["MSA"]?.try { |s| ModifiedSubsequentAvailability.parse(s) },
        s: values["S"]?.try { |s| Safety.parse(s) },
        au: values["AU"]?.try { |s| Automatable.parse(s) },
        r: values["R"]?.try { |s| Recovery.parse(s) },
        v: values["V"]?.try { |s| ValueDensity.parse(s) },
        re: values["RE"]?.try { |s| ResponseEffort.parse(s) },
        u: values["U"]?.try { |s| ProviderUrgency.parse(s) },
      )
    end

    # Return the *raw* code stored for a metric, or "X" if unset.
    def metric_value(name : String) : String
      case name
      when "AV"  then @av.code
      when "AC"  then @ac.code
      when "AT"  then @at.code
      when "PR"  then @pr.code
      when "UI"  then @ui.code
      when "VC"  then @vc.code
      when "VI"  then @vi.code
      when "VA"  then @va.code
      when "SC"  then @sc.code
      when "SI"  then @si.code
      when "SA"  then @sa.code
      when "E"   then @e.try(&.code) || "X"
      when "CR"  then @cr.try(&.code) || "X"
      when "IR"  then @ir.try(&.code) || "X"
      when "AR"  then @ar.try(&.code) || "X"
      when "MAV" then @mav.try(&.code) || "X"
      when "MAC" then @mac.try(&.code) || "X"
      when "MAT" then @mat.try(&.code) || "X"
      when "MPR" then @mpr.try(&.code) || "X"
      when "MUI" then @mui.try(&.code) || "X"
      when "MVC" then @mvc.try(&.code) || "X"
      when "MVI" then @mvi.try(&.code) || "X"
      when "MVA" then @mva.try(&.code) || "X"
      when "MSC" then @msc.try(&.code) || "X"
      when "MSI" then @msi.try(&.code) || "X"
      when "MSA" then @msa.try(&.code) || "X"
      when "S"   then @s.try(&.code) || "X"
      when "AU"  then @au.try(&.code) || "X"
      when "R"   then @r.try(&.code) || "X"
      when "V"   then @v.try(&.code) || "X"
      when "RE"  then @re.try(&.code) || "X"
      when "U"   then @u.try(&.code) || "X"
      else            raise CVSS::Error.new("unknown metric '#{name}'")
      end
    end

    # Mirror of the JS `m()` function — applies X-defaults and Modified
    # overrides when the score algorithm asks for an effective metric value.
    def effective_code(name : String) : String
      raw = metric_value(name)

      # Threat & Security Requirement worst-case defaults
      return "A" if name == "E" && raw == "X"
      return "H" if {"CR", "IR", "AR"}.includes?(name) && raw == "X"

      # Modified-overrides: only when "M<name>" is itself a base metric we track.
      if BASE_REQUIRED.includes?(name)
        modified = metric_value("M" + name)
        return modified unless modified == "X"
      end

      raw
    end

    def_equals_and_hash @av, @ac, @at, @pr, @ui,
      @vc, @vi, @va, @sc, @si, @sa,
      @e, @cr, @ir, @ar,
      @mav, @mac, @mat, @mpr, @mui,
      @mvc, @mvi, @mva, @msc, @msi, @msa,
      @s, @au, @r, @v, @re, @u

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
      !@ui.none?
    end

    # Vulnerable system has any non-None impact.
    def impacts_confidentiality? : Bool
      !@vc.none?
    end

    def impacts_integrity? : Bool
      !@vi.none?
    end

    def impacts_availability? : Bool
      !@va.none?
    end

    # Subsequent system has any non-None impact (any of SC/SI/SA != N).
    def impacts_subsequent_system? : Bool
      !@sc.none? || !@si.none? || !@sa.none?
    end

    # ───── Hash export ─────

    # Returns a `Hash(String, String)` of metric short-codes, in canonical
    # order. Optional metrics are only included when set. Note that
    # supplemental metric `U` (Provider Urgency) keeps its full word value
    # ("Clear" / "Green" / "Amber" / "Red") rather than a single letter.
    def to_h : Hash(String, String)
      h = {} of String => String
      h["AV"] = @av.code
      h["AC"] = @ac.code
      h["AT"] = @at.code
      h["PR"] = @pr.code
      h["UI"] = @ui.code
      h["VC"] = @vc.code
      h["VI"] = @vi.code
      h["VA"] = @va.code
      h["SC"] = @sc.code
      h["SI"] = @si.code
      h["SA"] = @sa.code
      h["E"] = @e.not_nil!.code if @e
      h["CR"] = @cr.not_nil!.code if @cr
      h["IR"] = @ir.not_nil!.code if @ir
      h["AR"] = @ar.not_nil!.code if @ar
      h["MAV"] = @mav.not_nil!.code if @mav
      h["MAC"] = @mac.not_nil!.code if @mac
      h["MAT"] = @mat.not_nil!.code if @mat
      h["MPR"] = @mpr.not_nil!.code if @mpr
      h["MUI"] = @mui.not_nil!.code if @mui
      h["MVC"] = @mvc.not_nil!.code if @mvc
      h["MVI"] = @mvi.not_nil!.code if @mvi
      h["MVA"] = @mva.not_nil!.code if @mva
      h["MSC"] = @msc.not_nil!.code if @msc
      h["MSI"] = @msi.not_nil!.code if @msi
      h["MSA"] = @msa.not_nil!.code if @msa
      h["S"] = @s.not_nil!.code if @s
      h["AU"] = @au.not_nil!.code if @au
      h["R"] = @r.not_nil!.code if @r
      h["V"] = @v.not_nil!.code if @v
      h["RE"] = @re.not_nil!.code if @re
      h["U"] = @u.not_nil!.code if @u
      h
    end

    # ───── Public scoring API ─────

    def base_score : Float64
      Score.score(self)
    end

    # In v4.0 the single score *is* the threat/environmental-aware score
    # (Threat metrics are part of the macro-vector). We expose aliases for
    # API symmetry with the v3 vector class.
    def threat_score : Float64
      base_score
    end

    def environmental_score : Float64
      base_score
    end

    def severity : Severity
      Severity.from_score(base_score)
    end

    # The 6-character MacroVector this vector falls into. Concatenates
    # `EQ1 EQ2 EQ3 EQ4 EQ5 EQ6` digits as defined in the CVSS v4.0 spec.
    #
    # ```
    # CVSS::V4::Vector.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").macro_vector
    # # => "000200"
    # ```
    def macro_vector : String
      Score.macro_vector(self)
    end

    # Vector nomenclature per CVSS v4.0 spec §6 — classifies the vector by
    # which optional metric groups are populated (Base only, +Threat,
    # +Environmental, or both).
    #
    # ```
    # vec = CVSS::V4::Vector.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    # vec.nomenclature.to_s  # => "CVSS-B"
    # vec.nomenclature.base? # => true
    # ```
    def nomenclature : Nomenclature
      t = threat_set?
      e = environmental_set?
      if t && e
        Nomenclature::BaseThreatEnvironmental
      elsif t
        Nomenclature::BaseThreat
      elsif e
        Nomenclature::BaseEnvironmental
      else
        Nomenclature::Base
      end
    end

    # True when the Threat metric group has a meaningful value (E set and not X).
    def threat_set? : Bool
      meaningful?(@e)
    end

    # True when any Environmental metric (Security Requirements or Modified base)
    # carries a meaningful (non-X) value.
    def environmental_set? : Bool
      meaningful?(@cr) || meaningful?(@ir) || meaningful?(@ar) ||
        meaningful?(@mav) || meaningful?(@mac) || meaningful?(@mat) ||
        meaningful?(@mpr) || meaningful?(@mui) ||
        meaningful?(@mvc) || meaningful?(@mvi) || meaningful?(@mva) ||
        meaningful?(@msc) || meaningful?(@msi) || meaningful?(@msa)
    end

    private def meaningful?(metric) : Bool
      !metric.nil? && !metric.not_defined?
    end

    # ───── Serialization ─────

    def to_s(io : IO) : Nil
      io << "CVSS:4.0"
      METRIC_ORDER.each do |key|
        case key
        when "AV"  then write_metric(io, key, @av.code)
        when "AC"  then write_metric(io, key, @ac.code)
        when "AT"  then write_metric(io, key, @at.code)
        when "PR"  then write_metric(io, key, @pr.code)
        when "UI"  then write_metric(io, key, @ui.code)
        when "VC"  then write_metric(io, key, @vc.code)
        when "VI"  then write_metric(io, key, @vi.code)
        when "VA"  then write_metric(io, key, @va.code)
        when "SC"  then write_metric(io, key, @sc.code)
        when "SI"  then write_metric(io, key, @si.code)
        when "SA"  then write_metric(io, key, @sa.code)
        when "E"   then write_optional(io, key, @e)
        when "CR"  then write_optional(io, key, @cr)
        when "IR"  then write_optional(io, key, @ir)
        when "AR"  then write_optional(io, key, @ar)
        when "MAV" then write_optional(io, key, @mav)
        when "MAC" then write_optional(io, key, @mac)
        when "MAT" then write_optional(io, key, @mat)
        when "MPR" then write_optional(io, key, @mpr)
        when "MUI" then write_optional(io, key, @mui)
        when "MVC" then write_optional(io, key, @mvc)
        when "MVI" then write_optional(io, key, @mvi)
        when "MVA" then write_optional(io, key, @mva)
        when "MSC" then write_optional(io, key, @msc)
        when "MSI" then write_optional(io, key, @msi)
        when "MSA" then write_optional(io, key, @msa)
        when "S"   then write_optional(io, key, @s)
        when "AU"  then write_optional(io, key, @au)
        when "R"   then write_optional(io, key, @r)
        when "V"   then write_optional(io, key, @v)
        when "RE"  then write_optional(io, key, @re)
        when "U"   then write_optional(io, key, @u)
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
