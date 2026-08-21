module CVSS::V1
  # Score computation for CVSS v1.0.
  # Spec: https://www.first.org/cvss/v1/guide (§2 "Scoring")
  module Score
    extend self

    private def round1(x : Float64) : Float64
      CVSS.round1(x)
    end

    # BaseScore = round_to_1_decimal(
    #   10 * AccessVector * AccessComplexity * Authentication
    #      * ((ConfImpact  * ConfImpactBias)
    #      +  (IntegImpact * IntegImpactBias)
    #      +  (AvailImpact * AvailImpactBias)))
    def base_score(v : Vector) : Float64
      biased_impact =
        (v.c.weight * v.b.conf_weight) +
          (v.i.weight * v.b.integ_weight) +
          (v.a.weight * v.b.avail_weight)

      round1(10.0 * v.av.weight * v.ac.weight * v.au.weight * biased_impact)
    end

    # TemporalScore = round_to_1_decimal(
    #   BaseScore * Exploitability * RemediationLevel * ReportConfidence)
    #
    # v1.0 has no "Not Defined" code, so an unset metric contributes the
    # neutral factor 1.0 and the result collapses to `base_score`.
    def temporal_score(v : Vector) : Float64
      e = v.e.try(&.weight) || 1.0
      rl = v.rl.try(&.weight) || 1.0
      rc = v.rc.try(&.weight) || 1.0
      round1(base_score(v) * e * rl * rc)
    end

    # EnvironmentalScore = round_to_1_decimal(
    #   (TemporalScore + ((10 - TemporalScore) * CollateralDamagePotential))
    #   * TargetDistribution)
    #
    # Unset metrics take their neutral values — CDP contributes 0.0 (no
    # upward correction, same as `CDP:N`) and TD contributes 1.0 (no
    # downward correction) — so an unscored environmental group collapses
    # to `temporal_score`. Note that `TD:N` legitimately zeroes the score:
    # a vulnerability present on no targets carries no environmental risk.
    def environmental_score(v : Vector) : Float64
      cdp = v.cdp.try(&.weight) || 0.0
      td = v.td.try(&.weight) || 1.0

      ts = temporal_score(v)
      round1((ts + ((10.0 - ts) * cdp)) * td)
    end
  end
end
