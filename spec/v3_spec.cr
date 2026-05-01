require "./spec_helper"

# Reference scores were taken from the FIRST CVSS v3.1 calculator and
# spec examples (https://www.first.org/cvss/calculator/3.1).
private def parse(s)
  CVSS::V3::Vector.parse(s)
end

describe CVSS::V3::Vector do
  describe ".parse" do
    it "parses a canonical v3.1 vector" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      v.version.should eq("3.1")
      v.av.should eq(CVSS::V3::AttackVector::Network)
      v.s.should eq(CVSS::V3::Scope::Unchanged)
      v.c.should eq(CVSS::V3::Impact::High)
    end

    it "rejects unknown metrics" do
      expect_raises(CVSS::ParseError, /unknown/) do
        parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:Y")
      end
    end

    it "rejects duplicate metrics" do
      expect_raises(CVSS::ParseError, /duplicate/) do
        parse("CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      end
    end

    it "rejects missing base metrics" do
      expect_raises(CVSS::ParseError, /missing required/) do
        parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")
      end
    end

    it "rejects malformed input" do
      expect_raises(CVSS::ParseError) { parse("CVSS:3.1/AV:N/AC") }
      expect_raises(CVSS::ParseError) { parse("CVSS:3.1/") }
      expect_raises(CVSS::ParseError) { parse("CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") }
    end

    it "rejects bad metric values" do
      expect_raises(CVSS::InvalidMetricError) do
        parse("CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      end
    end
  end

  describe "base_score" do
    it "scores 9.8 critical for fully-network HHH" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      v.base_score.should eq(9.8)
      v.severity.should eq(CVSS::Severity::Critical)
    end

    it "scores 7.5 high for availability-only network" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
      v.base_score.should eq(7.5)
      v.severity.should eq(CVSS::Severity::High)
    end

    it "scores 6.1 medium for reflected XSS-like vector" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
      v.base_score.should eq(6.1)
      v.severity.should eq(CVSS::Severity::Medium)
    end

    it "scores 6.7 medium for local privileged HHH" do
      v = parse("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
      v.base_score.should eq(6.7)
    end

    it "scores 0.0 none when there is no impact" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N")
      v.base_score.should eq(0.0)
      v.severity.should eq(CVSS::Severity::None)
    end

    it "applies the v3.0 RoundUp rather than v3.1" do
      v30 = parse("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
      v30.base_score.should eq(8.1)
      v30.version.should eq("3.0")
    end
  end

  describe "temporal_score" do
    it "matches base when no temporal metrics are set" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      v.temporal_score.should eq(v.base_score)
    end

    it "applies E/RL/RC multipliers" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C")
      # 9.8 * 0.97 * 0.95 * 1.0 = 9.0307 → roundup31 → 9.1
      v.temporal_score.should eq(9.1)
    end
  end

  describe "environmental_score" do
    it "falls back to base when no environmental metrics are set" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      v.environmental_score.should eq(9.8)
    end

    it "downgrades base 9.8 to env 6.3 when MI/MA neutralize integrity+availability" do
      # Cross-checked with the FIRST v3.1 calculator.
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R" \
                "/CR:H/IR:H/AR:M/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:H/MI:N/MA:N")
      v.base_score.should eq(9.8)
      v.environmental_score.should eq(6.3)
    end

    it "honors Modified Scope = Changed in env score" do
      # Same base, but MS:C and MPR:L use the changed-scope PR weight (0.68).
      v = parse("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" \
                "/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:L/MUI:N/MS:C/MC:H/MI:H/MA:H")
      v.environmental_score.should be > v.base_score
    end
  end

  describe "to_s" do
    it "round-trips a base vector" do
      s = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      parse(s).to_s.should eq(s)
    end

    it "round-trips a vector with temporal+environmental" do
      s = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R" \
          "/CR:H/IR:H/AR:M/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:H/MI:N/MA:N"
      parse(s).to_s.should eq(s)
    end

    it "preserves declared CVSS version" do
      s = "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
      parse(s).to_s.should eq(s)
    end
  end

  describe "Scope:Changed base scoring" do
    it "uses the polynomial impact formula" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
      v.base_score.should eq(9.9)
      v.impact_subscore.should be_close(6.048, 0.01)
    end

    it "applies the changed-scope PR weight (0.68 for L instead of 0.62)" do
      # Same vector, only Scope flipped — PR:L weight differs (0.62 vs 0.68).
      sc_unchanged = parse("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
      sc_changed = parse("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
      # Changed scope should produce a higher exploitability subscore
      # (PR:L worth more) AND a higher base score from the 1.08 multiplier.
      sc_changed.exploitability_subscore.should be > sc_unchanged.exploitability_subscore
      sc_changed.base_score.should be > sc_unchanged.base_score
    end
  end

  describe "v3.0 vs v3.1 environmental formula difference" do
    it "produces different scores for the same Modified-Scope:Changed vector" do
      tail = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H/CR:H/IR:H/AR:H/MC:H/MI:H/MA:H"
      v30 = parse("CVSS:3.0/" + tail)
      v31 = parse("CVSS:3.1/" + tail)
      # v3.0 uses (iss-0.02)^15; v3.1 uses (iss*0.9731-0.02)^13.
      v30.environmental_score.should eq(9.9)
      v31.environmental_score.should eq(10.0)
    end
  end

  describe "Vector.new with bad version" do
    it "rejects a version that isn't 3.0 or 3.1" do
      expect_raises(CVSS::Error, /unsupported v3 version/) do
        CVSS::V3::Vector.new(
          av: CVSS::V3::AttackVector::Network,
          ac: CVSS::V3::AttackComplexity::Low,
          pr: CVSS::V3::PrivilegesRequired::None,
          ui: CVSS::V3::UserInteraction::None,
          s: CVSS::V3::Scope::Unchanged,
          c: CVSS::V3::Impact::High,
          i: CVSS::V3::Impact::High,
          a: CVSS::V3::Impact::High,
          version: "9.9",
        )
      end
    end
  end

  describe "sub-scores" do
    it "exposes ISS / impact / exploitability subscores for tooling" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      # ISS = 1 - (1-0.56)^3 = 0.914816
      v.iss.should be_close(0.914816, 0.0001)
      # impact = 6.42 * ISS = 5.873
      v.impact_subscore.should be_close(5.873, 0.001)
      # exploitability = 8.22 * 0.85 * 0.77 * 0.85 * 0.85 = 3.887
      v.exploitability_subscore.should be_close(3.887, 0.001)
    end

    it "uses the changed-scope formula when S:C" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N")
      # Changed scope uses the polynomial formula and PR changed-scope weight.
      v.impact_subscore.should be > 0
    end
  end

  describe ".parse?" do
    it "returns nil on bad input" do
      CVSS::V3::Vector.parse?("CVSS:3.1/AV:N/AC:L").should be_nil
    end
  end

  describe "Equality" do
    it "two parsed vectors with the same string are ==" do
      a = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F")
      b = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F")
      a.should eq(b)
    end

    it "differs when an optional metric differs" do
      a = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      b = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U")
      a.should_not eq(b)
    end
  end

  describe "Classification helpers" do
    it "tags a network attack with no privileges" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      v.network?.should be_true
      v.physical?.should be_false
      v.requires_privileges?.should be_false
      v.requires_user_interaction?.should be_false
      v.scope_changed?.should be_false
    end

    it "tags a privileged local attack" do
      v = parse("CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H")
      v.network?.should be_false
      v.local?.should be_true
      v.requires_privileges?.should be_true
      v.requires_user_interaction?.should be_true
      v.scope_changed?.should be_true
    end

    it "tracks per-CIA impact" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
      v.impacts_confidentiality?.should be_true
      v.impacts_integrity?.should be_false
      v.impacts_availability?.should be_false
    end

    it "covers all four AV branches" do
      parse("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").adjacent_network?.should be_true
      parse("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").physical?.should be_true
    end

    it "scope_unchanged? mirrors scope_changed?" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      v.scope_unchanged?.should be_true
      v.scope_changed?.should be_false
    end
  end

  describe "metric_value" do
    it "returns short codes for base metrics" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      v.metric_value("AV").should eq("N")
      v.metric_value("S").should eq("U")
      v.metric_value("C").should eq("H")
    end

    it "returns 'X' for unset optional metrics" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      v.metric_value("E").should eq("X")
      v.metric_value("MAV").should eq("X")
    end

    it "returns the stored code for set optional metrics" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/MAV:L")
      v.metric_value("E").should eq("F")
      v.metric_value("MAV").should eq("L")
    end

    it "raises on unknown metric names" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      expect_raises(CVSS::Error, /unknown/) { v.metric_value("ZZ") }
    end
  end

  describe "to_h" do
    it "returns metric short-codes in canonical order" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      v.to_h.should eq({
        "AV" => "N", "AC" => "L", "PR" => "N", "UI" => "N",
        "S" => "U", "C" => "H", "I" => "H", "A" => "H",
      })
    end

    it "includes optional metrics only when set" do
      v = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/MAV:L")
      h = v.to_h
      h["E"].should eq("F")
      h["MAV"].should eq("L")
      h.has_key?("RL").should be_false
    end

    it "captures every modified-base + environmental metric" do
      s = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" \
          "/E:F/RL:O/RC:R/CR:H/IR:M/AR:L" \
          "/MAV:A/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N"
      h = parse(s).to_h
      %w[E RL RC CR IR AR MAV MAC MPR MUI MS MC MI MA].each do |k|
        h.has_key?(k).should be_true
      end
      h["MS"].should eq("C")
      h["MA"].should eq("N")
    end
  end

  describe "RoundUp" do
    it "rounds 4.65 up to 4.7 (v3.1)" do
      CVSS::V3::Score.roundup31(4.65).should eq(4.7)
    end

    it "rounds 4.6 to itself (v3.1)" do
      CVSS::V3::Score.roundup31(4.6).should eq(4.6)
    end

    it "rounds 4.65 up to 4.7 (v3.0 ceiling)" do
      CVSS::V3::Score.roundup30(4.65).should eq(4.7)
    end
  end
end
