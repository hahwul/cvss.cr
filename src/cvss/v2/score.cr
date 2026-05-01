module CVSS::V2
  # Score computation for CVSS v2.0.
  # Spec: https://www.first.org/cvss/v2/guide
  module Score
    extend self

    private def round1(x : Float64) : Float64
      CVSS.round1(x)
    end

    private def impact(v : Vector) : Float64
      10.41 * (1.0 - (1.0 - v.c.weight) * (1.0 - v.i.weight) * (1.0 - v.a.weight))
    end

    private def exploitability(v : Vector) : Float64
      20.0 * v.av.weight * v.ac.weight * v.au.weight
    end

    private def f_impact(impact : Float64) : Float64
      impact == 0.0 ? 0.0 : 1.176
    end

    def base_score(v : Vector) : Float64
      i = impact(v)
      e = exploitability(v)
      round1(((0.6 * i) + (0.4 * e) - 1.5) * f_impact(i))
    end

    def temporal_score(v : Vector) : Float64
      e = (v.e || Exploitability::NotDefined).weight
      rl = (v.rl || RemediationLevel::NotDefined).weight
      rc = (v.rc || ReportConfidence::NotDefined).weight
      round1(base_score(v) * e * rl * rc)
    end

    def environmental_score(v : Vector) : Float64
      cr = (v.cr || SecurityRequirement::NotDefined).weight
      ir = (v.ir || SecurityRequirement::NotDefined).weight
      ar = (v.ar || SecurityRequirement::NotDefined).weight
      cdp = (v.cdp || CollateralDamagePotential::NotDefined).weight
      td = (v.td || TargetDistribution::NotDefined).weight

      adjusted_impact = {10.0,
                         10.41 * (1.0 - (1.0 - v.c.weight * cr) * (1.0 - v.i.weight * ir) * (1.0 - v.a.weight * ar))}.min

      e = (v.e || Exploitability::NotDefined).weight
      rl = (v.rl || RemediationLevel::NotDefined).weight
      rc = (v.rc || ReportConfidence::NotDefined).weight

      adjusted_base = round1(((0.6 * adjusted_impact) + (0.4 * exploitability(v)) - 1.5) * f_impact(adjusted_impact))
      adjusted_temporal = round1(adjusted_base * e * rl * rc)

      round1((adjusted_temporal + (10.0 - adjusted_temporal) * cdp) * td)
    end
  end
end
