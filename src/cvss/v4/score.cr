module CVSS::V4
  # Score computation for CVSS v4.0.
  # Algorithm ported from FIRSTdotorg/cvss-v4-calculator (BSD-2-Clause).
  module Score
    extend self

    # Per-metric "level" tables — used to compute severity distance from a
    # given max-severity vector. Step is 0.1 per index.
    AV_LEVELS = {"N" => 0.0, "A" => 0.1, "L" => 0.2, "P" => 0.3}
    PR_LEVELS = {"N" => 0.0, "L" => 0.1, "H" => 0.2}
    UI_LEVELS = {"N" => 0.0, "P" => 0.1, "A" => 0.2}

    AC_LEVELS = {"L" => 0.0, "H" => 0.1}
    AT_LEVELS = {"N" => 0.0, "P" => 0.1}

    VC_LEVELS = {"H" => 0.0, "L" => 0.1, "N" => 0.2}
    VI_LEVELS = {"H" => 0.0, "L" => 0.1, "N" => 0.2}
    VA_LEVELS = {"H" => 0.0, "L" => 0.1, "N" => 0.2}

    SC_LEVELS = {"H" => 0.1, "L" => 0.2, "N" => 0.3}
    SI_LEVELS = {"S" => 0.0, "H" => 0.1, "L" => 0.2, "N" => 0.3}
    SA_LEVELS = {"S" => 0.0, "H" => 0.1, "L" => 0.2, "N" => 0.3}

    CR_LEVELS = {"H" => 0.0, "M" => 0.1, "L" => 0.2}
    IR_LEVELS = {"H" => 0.0, "M" => 0.1, "L" => 0.2}
    AR_LEVELS = {"H" => 0.0, "M" => 0.1, "L" => 0.2}

    STEP = 0.1

    # Pre-parsed max-severity levels per EQ class to avoid runtime string parsing.
    EQ1_MAX_LEVELS = {
      0 => [{0.0, 0.0, 0.0}],
      1 => [{0.1, 0.0, 0.0}, {0.0, 0.1, 0.0}, {0.0, 0.0, 0.1}],
      2 => [{0.3, 0.0, 0.0}, {0.1, 0.1, 0.1}],
    }

    EQ2_MAX_LEVELS = {
      0 => [{0.0, 0.0}],
      1 => [{0.1, 0.0}, {0.0, 0.1}],
    }

    EQ3_EQ6_MAX_LEVELS = {
      0 => {
        0 => [{0.0, 0.0, 0.0, 0.0, 0.0, 0.0}],
        1 => [{0.0, 0.0, 0.1, 0.1, 0.1, 0.0}, {0.0, 0.0, 0.0, 0.1, 0.1, 0.1}],
      },
      1 => {
        0 => [{0.1, 0.0, 0.0, 0.0, 0.0, 0.0}, {0.0, 0.1, 0.0, 0.0, 0.0, 0.0}],
        1 => [{0.1, 0.0, 0.1, 0.0, 0.1, 0.0}, {0.1, 0.0, 0.0, 0.0, 0.1, 0.1},
              {0.0, 0.1, 0.0, 0.1, 0.0, 0.1}, {0.0, 0.1, 0.1, 0.1, 0.0, 0.0},
              {0.1, 0.1, 0.0, 0.0, 0.0, 0.1}],
      },
      2 => {
        1 => [{0.1, 0.1, 0.1, 0.0, 0.0, 0.0}],
      },
    }

    EQ4_MAX_LEVELS = {
      0 => [{0.1, 0.0, 0.0}],
      1 => [{0.1, 0.1, 0.1}],
      2 => [{0.2, 0.2, 0.2}],
    }

    def score(v : Vector) : Float64
      # Shortcut: no impact at all → 0.0.
      if {"VC", "VI", "VA", "SC", "SI", "SA"}.all? { |m| v.effective_code(m) == "N" }
        return 0.0
      end

      mv = macro_vector(v)
      value = MacroVectorTables::LOOKUP[mv]?
      raise CVSS::Error.new("infeasible macro vector #{mv} — should be unreachable") if value.nil?

      eq1 = mv[0].to_i
      eq2 = mv[1].to_i
      eq3 = mv[2].to_i
      eq4 = mv[3].to_i
      eq5 = mv[4].to_i
      eq6 = mv[5].to_i

      # Next-lower neighbor macros (each EQ digit + 1).
      score_eq1_lower = MacroVectorTables::LOOKUP["#{eq1 + 1}#{eq2}#{eq3}#{eq4}#{eq5}#{eq6}"]?
      score_eq2_lower = MacroVectorTables::LOOKUP["#{eq1}#{eq2 + 1}#{eq3}#{eq4}#{eq5}#{eq6}"]?

      # EQ3+EQ6 are joint — multiple branches, one of them tries both directions.
      score_eq3eq6_lower =
        case {eq3, eq6}
        when {0, 0}
          left = MacroVectorTables::LOOKUP["#{eq1}#{eq2}#{eq3}#{eq4}#{eq5}#{eq6 + 1}"]?
          right = MacroVectorTables::LOOKUP["#{eq1}#{eq2}#{eq3 + 1}#{eq4}#{eq5}#{eq6}"]?
          if left && right
            {left, right}.max
          else
            left || right
          end
        when {0, 1}
          MacroVectorTables::LOOKUP["#{eq1}#{eq2}#{eq3 + 1}#{eq4}#{eq5}#{eq6}"]?
        when {1, 0}
          MacroVectorTables::LOOKUP["#{eq1}#{eq2}#{eq3}#{eq4}#{eq5}#{eq6 + 1}"]?
        when {1, 1}
          MacroVectorTables::LOOKUP["#{eq1}#{eq2}#{eq3 + 1}#{eq4}#{eq5}#{eq6}"]?
        else
          # (2, 1) → (3, 2): does not exist
          MacroVectorTables::LOOKUP["#{eq1}#{eq2}#{eq3 + 1}#{eq4}#{eq5}#{eq6 + 1}"]?
        end

      score_eq4_lower = MacroVectorTables::LOOKUP["#{eq1}#{eq2}#{eq3}#{eq4 + 1}#{eq5}#{eq6}"]?
      score_eq5_lower = MacroVectorTables::LOOKUP["#{eq1}#{eq2}#{eq3}#{eq4}#{eq5 + 1}#{eq6}"]?

      # Pre-evaluate effective code levels once
      eff_av = AV_LEVELS[v.effective_code("AV")]
      eff_pr = PR_LEVELS[v.effective_code("PR")]
      eff_ui = UI_LEVELS[v.effective_code("UI")]
      eff_ac = AC_LEVELS[v.effective_code("AC")]
      eff_at = AT_LEVELS[v.effective_code("AT")]
      eff_vc = VC_LEVELS[v.effective_code("VC")]
      eff_vi = VI_LEVELS[v.effective_code("VI")]
      eff_va = VA_LEVELS[v.effective_code("VA")]
      eff_sc = SC_LEVELS[v.effective_code("SC")]
      eff_si = SI_LEVELS[v.effective_code("SI")]
      eff_sa = SA_LEVELS[v.effective_code("SA")]
      eff_cr = CR_LEVELS[v.effective_code("CR")]
      eff_ir = IR_LEVELS[v.effective_code("IR")]
      eff_ar = AR_LEVELS[v.effective_code("AR")]

      # EQ1 severity distance: find the first matching max-level tuple
      cur_sd_eq1 = 0.0
      EQ1_MAX_LEVELS[eq1].each do |m_av, m_pr, m_ui|
        sd_av = eff_av - m_av
        sd_pr = eff_pr - m_pr
        sd_ui = eff_ui - m_ui
        if sd_av >= 0 && sd_pr >= 0 && sd_ui >= 0
          cur_sd_eq1 = sd_av + sd_pr + sd_ui
          break
        end
      end

      # EQ2 severity distance: find the first matching max-level tuple
      cur_sd_eq2 = 0.0
      EQ2_MAX_LEVELS[eq2].each do |m_ac, m_at|
        sd_ac = eff_ac - m_ac
        sd_at = eff_at - m_at
        if sd_ac >= 0 && sd_at >= 0
          cur_sd_eq2 = sd_ac + sd_at
          break
        end
      end

      # EQ3 severity distance: find the first matching max-level tuple
      cur_sd_eq3eq6 = 0.0
      EQ3_EQ6_MAX_LEVELS[eq3][eq6].each do |m_vc, m_vi, m_va, m_cr, m_ir, m_ar|
        sd_vc = eff_vc - m_vc
        sd_vi = eff_vi - m_vi
        sd_va = eff_va - m_va
        sd_cr = eff_cr - m_cr
        sd_ir = eff_ir - m_ir
        sd_ar = eff_ar - m_ar
        if sd_vc >= 0 && sd_vi >= 0 && sd_va >= 0 && sd_cr >= 0 && sd_ir >= 0 && sd_ar >= 0
          cur_sd_eq3eq6 = sd_vc + sd_vi + sd_va + sd_cr + sd_ir + sd_ar
          break
        end
      end

      # EQ4 severity distance: find the first matching max-level tuple
      cur_sd_eq4 = 0.0
      EQ4_MAX_LEVELS[eq4].each do |m_sc, m_si, m_sa|
        sd_sc = eff_sc - m_sc
        sd_si = eff_si - m_si
        sd_sa = eff_sa - m_sa
        if sd_sc >= 0 && sd_si >= 0 && sd_sa >= 0
          cur_sd_eq4 = sd_sc + sd_si + sd_sa
          break
        end
      end

      # Convert max-severity depths to score units.
      max_sev_eq1 = MacroVectorTables::MAX_SEVERITY_EQ1[eq1] * STEP
      max_sev_eq2 = MacroVectorTables::MAX_SEVERITY_EQ2[eq2] * STEP
      max_sev_eq3eq6 = MacroVectorTables::MAX_SEVERITY_EQ3_EQ6[eq3][eq6] * STEP
      max_sev_eq4 = MacroVectorTables::MAX_SEVERITY_EQ4[eq4] * STEP

      # For each EQ that has a lower neighbor: contribute a normalized distance.
      normalized = 0.0
      n_lower = 0

      if avail = score_eq1_lower
        n_lower += 1
        normalized += (value - avail) * (cur_sd_eq1 / max_sev_eq1)
      end
      if avail = score_eq2_lower
        n_lower += 1
        normalized += (value - avail) * (cur_sd_eq2 / max_sev_eq2)
      end
      if avail = score_eq3eq6_lower
        n_lower += 1
        normalized += (value - avail) * (cur_sd_eq3eq6 / max_sev_eq3eq6)
      end
      if avail = score_eq4_lower
        n_lower += 1
        normalized += (value - avail) * (cur_sd_eq4 / max_sev_eq4)
      end
      # EQ5's normalised contribution is always zero (spec hardcodes the
      # percent to 0), but having a lower neighbour still counts toward
      # `n_lower` and so dilutes the mean — pulling the score down.
      n_lower += 1 if score_eq5_lower

      mean_distance = n_lower == 0 ? 0.0 : normalized / n_lower
      result = value - mean_distance
      result = 0.0 if result < 0
      result = 10.0 if result > 10
      ((result * 10.0 + 0.5).floor) / 10.0
    end

    # Compute the 6-character macro vector from the input.
    def macro_vector(v : Vector) : String
      av = v.effective_code("AV")
      pr = v.effective_code("PR")
      ui = v.effective_code("UI")
      ac = v.effective_code("AC")
      at = v.effective_code("AT")
      vc = v.effective_code("VC")
      vi = v.effective_code("VI")
      va = v.effective_code("VA")
      sc = v.effective_code("SC")
      si = v.effective_code("SI")
      sa = v.effective_code("SA")
      cr = v.effective_code("CR")
      ir = v.effective_code("IR")
      ar = v.effective_code("AR")
      e = v.effective_code("E")
      msi = v.effective_code("MSI")
      msa = v.effective_code("MSA")

      eq1 =
        if av == "N" && pr == "N" && ui == "N"
          "0"
        elsif (av == "N" || pr == "N" || ui == "N") &&
              !(av == "N" && pr == "N" && ui == "N") &&
              av != "P"
          "1"
        else # av == "P" or none of AV/PR/UI is N
          "2"
        end

      eq2 = (ac == "L" && at == "N") ? "0" : "1"

      eq3 =
        if vc == "H" && vi == "H"
          "0"
        elsif vc == "H" || vi == "H" || va == "H"
          "1"
        else
          "2"
        end

      eq4 =
        if msi == "S" || msa == "S"
          "0"
        elsif sc == "H" || si == "H" || sa == "H"
          "1"
        else
          "2"
        end

      eq5 =
        case e
        when "A" then "0"
        when "P" then "1"
        else          "2" # "U"
        end

      eq6 =
        if (cr == "H" && vc == "H") || (ir == "H" && vi == "H") || (ar == "H" && va == "H")
          "0"
        else
          "1"
        end

      "#{eq1}#{eq2}#{eq3}#{eq4}#{eq5}#{eq6}"
    end
  end
end
