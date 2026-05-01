module CVSS::V3
  # Score computation for CVSS v3.0 / v3.1.
  #
  # Section references in this module point at the official specs:
  #   - CVSS v3.0: https://www.first.org/cvss/v3.0/specification-document
  #   - CVSS v3.1: https://www.first.org/cvss/v3.1/specification-document
  module Score
    extend self

    # CVSS v3.1 RoundUp (spec §7.1).
    #
    # Avoids the floating-point traps in the v3.0 ceiling/10 formulation by
    # working in integer space first.
    def roundup31(input : Float64) : Float64
      int_input = (input * 100_000.0).round.to_i64
      if int_input.remainder(10_000) == 0
        int_input.to_f / 100_000.0
      else
        ((int_input // 10_000) + 1).to_f / 10.0
      end
    end

    # CVSS v3.0 RoundUp = ceiling(input * 10) / 10. The intermediate
    # multiplication is run through an integer round-trip so values like
    # `4.65 * 10 = 46.4999...` don't quietly become 4.6.
    def roundup30(input : Float64) : Float64
      int_input = (input * 100_000.0).round.to_i64
      ((int_input + 9_999) // 10_000).to_f / 10.0
    end

    def roundup(input : Float64, version : String) : Float64
      version == "3.0" ? roundup30(input) : roundup31(input)
    end

    # ───── Sub-scores (exposed for tooling / debugging) ─────

    # Impact Sub-Score (ISS) — the raw impact value before scope-aware scaling.
    #   ISS = 1 - ((1 - C) × (1 - I) × (1 - A))
    def iss(v : Vector) : Float64
      1.0 - ((1.0 - v.c.weight) * (1.0 - v.i.weight) * (1.0 - v.a.weight))
    end

    # Impact subscore — scaled by Scope.
    def impact(v : Vector) : Float64
      i = iss(v)
      if v.s.unchanged?
        6.42 * i
      else
        7.52 * (i - 0.029) - 3.25 * ((i - 0.02) ** 15)
      end
    end

    # Exploitability subscore.
    def exploitability(v : Vector) : Float64
      8.22 * v.av.weight * v.ac.weight * v.pr.weight(v.s) * v.ui.weight
    end

    # ───── Base score ─────

    def base_score(v : Vector) : Float64
      i = impact(v)
      return 0.0 if i <= 0

      e = exploitability(v)
      raw =
        if v.s.unchanged?
          {i + e, 10.0}.min
        else
          {1.08 * (i + e), 10.0}.min
        end

      roundup(raw, v.version)
    end

    # ───── Temporal score ─────

    # Returns base_score if no temporal metrics are set (all default to X).
    def temporal_score(v : Vector) : Float64
      e = (v.e || ExploitCodeMaturity::NotDefined).weight
      rl = (v.rl || RemediationLevel::NotDefined).weight
      rc = (v.rc || ReportConfidence::NotDefined).weight
      roundup(base_score(v) * e * rl * rc, v.version)
    end

    # ───── Environmental score ─────

    def environmental_score(v : Vector) : Float64
      cr = (v.cr || SecurityRequirement::NotDefined).weight
      ir = (v.ir || SecurityRequirement::NotDefined).weight
      ar = (v.ar || SecurityRequirement::NotDefined).weight

      mav = (v.mav || ModifiedAttackVector::NotDefined).weight(v.av)
      mac = (v.mac || ModifiedAttackComplexity::NotDefined).weight(v.ac)
      ms_effective = (v.ms || ModifiedScope::NotDefined).effective(v.s)
      mpr = (v.mpr || ModifiedPrivilegesRequired::NotDefined).weight(v.pr, ms_effective)
      mui = (v.mui || ModifiedUserInteraction::NotDefined).weight(v.ui)

      mc = (v.mc || ModifiedImpact::NotDefined).weight(v.c)
      mi = (v.mi || ModifiedImpact::NotDefined).weight(v.i)
      ma = (v.ma || ModifiedImpact::NotDefined).weight(v.a)

      modified_iss = {1.0 - ((1.0 - mc * cr) * (1.0 - mi * ir) * (1.0 - ma * ar)), 0.915}.min

      modified_impact =
        if ms_effective.unchanged?
          6.42 * modified_iss
        else
          if v.version == "3.0"
            7.52 * (modified_iss - 0.029) - 3.25 * ((modified_iss - 0.02) ** 15)
          else
            7.52 * (modified_iss - 0.029) - 3.25 * ((modified_iss * 0.9731 - 0.02) ** 13)
          end
        end

      return 0.0 if modified_impact <= 0

      modified_exploitability = 8.22 * mav * mac * mpr * mui

      e = (v.e || ExploitCodeMaturity::NotDefined).weight
      rl = (v.rl || RemediationLevel::NotDefined).weight
      rc = (v.rc || ReportConfidence::NotDefined).weight

      inner =
        if ms_effective.unchanged?
          roundup({modified_impact + modified_exploitability, 10.0}.min, v.version)
        else
          roundup({1.08 * (modified_impact + modified_exploitability), 10.0}.min, v.version)
        end

      roundup(inner * e * rl * rc, v.version)
    end
  end
end
