require "./spec_helper"

# Reference scores come from two places:
#
#   * the three worked examples in the FIRST CVSS v1 guide
#     (https://www.first.org/cvss/v1/guide §3.1), and
#   * CVSS v1 vectors NVD published between 2005 and 2007, captured from
#     the Internet Archive (nvd.nist.gov/nvd.cfm?cvename=...).
private def parse(s)
  CVSS::V1::Vector.parse(s)
end

describe CVSS::V1::Vector do
  describe ".parse" do
    it "parses the parenthesised NVD notation" do
      v = parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)")
      v.version.should eq("1.0")
      v.av.should eq(CVSS::V1::AccessVector::Remote)
      v.ac.should eq(CVSS::V1::AccessComplexity::Low)
      v.au.should eq(CVSS::V1::Authentication::NotRequired)
      v.b.should eq(CVSS::V1::ImpactBias::Normal)
    end

    it "parses without the surrounding parentheses" do
      parse("AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N").base_score.should eq(10.0)
    end

    it "tolerates an explicit CVSS:1.0/ prefix" do
      parse("CVSS:1.0/(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)").base_score.should eq(10.0)
      parse("CVSS:1.0/AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N").base_score.should eq(10.0)
    end

    it "parses appended temporal metrics" do
      v = parse("(AV:L/AC:H/Au:NR/C:N/I:P/A:C/B:C/E:U/RL:O/RC:U)")
      v.e.should eq(CVSS::V1::Exploitability::Unproven)
      v.rl.should eq(CVSS::V1::RemediationLevel::OfficialFix)
      v.rc.should eq(CVSS::V1::ReportConfidence::Unconfirmed)
    end

    it "accepts both spellings of RC:Uc" do
      parse("(AV:R/AC:L/Au:R/C:C/I:N/A:P/B:N/E:P/RL:T/RC:Uc)").rc
        .should eq(CVSS::V1::ReportConfidence::Uncorroborated)
      parse("(AV:R/AC:L/Au:R/C:C/I:N/A:P/B:N/E:P/RL:T/RC:UC)").rc
        .should eq(CVSS::V1::ReportConfidence::Uncorroborated)
    end

    it "rejects missing base metrics" do
      expect_raises(CVSS::ParseError, /missing required/) do
        parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C)")
      end
    end

    it "rejects unbalanced parentheses" do
      expect_raises(CVSS::ParseError, /unbalanced/) do
        parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N")
      end
    end

    it "rejects duplicate metrics" do
      expect_raises(CVSS::ParseError, /duplicate/) do
        parse("(AV:R/AV:L/AC:L/Au:NR/C:C/I:C/A:C/B:N)")
      end
    end

    it "rejects unknown metrics" do
      expect_raises(CVSS::ParseError, /unknown CVSS v1 metric/) do
        parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N/PR:N)")
      end
    end

    it "rejects bad values" do
      expect_raises(CVSS::InvalidMetricError) do
        parse("(AV:N/AC:L/Au:NR/C:C/I:C/A:C/B:N)")
      end
      expect_raises(CVSS::InvalidMetricError, /invalid B value/) do
        parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:X)")
      end
    end
  end

  describe ".parse?" do
    it "returns nil instead of raising" do
      CVSS::V1::Vector.parse?("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)").should_not be_nil
      CVSS::V1::Vector.parse?("garbage").should be_nil
    end
  end

  describe "base_score" do
    # FIRST CVSS v1 guide §3.1, CVE-2002-0392 (Apache chunked encoding).
    it "scores 8.5 for the Apache chunked-encoding example" do
      parse("(AV:R/AC:L/Au:NR/C:P/I:P/A:C/B:A)").base_score.should eq(8.5)
    end

    # FIRST CVSS v1 guide §3.1, CAN-2003-0818 (Microsoft ASN.1).
    it "scores 10.0 for the ASN.1 example" do
      parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)").base_score.should eq(10.0)
    end

    # FIRST CVSS v1 guide §3.1, CVE-2003-0062 (NOD32).
    it "scores 5.6 for the NOD32 example" do
      parse("(AV:L/AC:H/Au:NR/C:C/I:C/A:C/B:N)").base_score.should eq(5.6)
    end

    it "matches the v1 vectors NVD published" do
      {
        # CVE-2006-3439
        "(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)" => 10.0,
        # CVE-2006-1234
        "(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)" => 5.6,
        # CVE-2006-0987
        "(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)" => 2.3,
        # CVE-2006-2842 and CVE-2005-4560
        "(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)" => 7.0,
      }.each do |vector, score|
        parse(vector).base_score.should eq(score)
      end
    end

    it "scores 0.0 when nothing is impacted" do
      parse("(AV:R/AC:L/Au:NR/C:N/I:N/A:N/B:N)").base_score.should eq(0.0)
    end

    it "weights the biased impact metric higher" do
      conf = parse("(AV:R/AC:L/Au:NR/C:C/I:N/A:N/B:C)").base_score
      normal = parse("(AV:R/AC:L/Au:NR/C:C/I:N/A:N/B:N)").base_score
      conf.should eq(5.0)
      normal.should eq(3.3)
      conf.should be > normal
    end

    it "discounts local access and required authentication" do
      parse("(AV:L/AC:L/Au:R/C:C/I:C/A:C/B:N)").base_score.should eq(4.2)
    end
  end

  describe "temporal_score" do
    it "falls back to base_score when no temporal metrics are set" do
      v = parse("(AV:R/AC:L/Au:NR/C:P/I:P/A:C/B:A)")
      v.temporal_score.should eq(v.base_score)
    end

    # The guide's example tables label Official-Fix "(0.90)", but only the
    # normative 0.87 reproduces the printed 7.0 / 8.3 / 4.4 results.
    it "scores 7.0 for the Apache example" do
      parse("(AV:R/AC:L/Au:NR/C:P/I:P/A:C/B:A/E:F/RL:O/RC:C)")
        .temporal_score.should eq(7.0)
    end

    it "scores 8.3 for the ASN.1 example" do
      parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N/E:F/RL:O/RC:C)")
        .temporal_score.should eq(8.3)
    end

    it "scores 4.4 for the NOD32 example" do
      parse("(AV:L/AC:H/Au:NR/C:C/I:C/A:C/B:N/E:P/RL:O/RC:C)")
        .temporal_score.should eq(4.4)
    end

    it "never exceeds the base score" do
      v = parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N/E:U/RL:O/RC:U)")
      v.temporal_score.should be <= v.base_score
    end
  end

  describe "environmental_score" do
    it "falls back to temporal_score when no environmental metrics are set" do
      v = parse("(AV:R/AC:L/Au:NR/C:P/I:P/A:C/B:A/E:F/RL:O/RC:C)")
      v.environmental_score.should eq(v.temporal_score)
    end

    # Guide §3.1 states the Apache example ranges 0.0 ("None", "None") to
    # 8.5 ("High", "High"); ASN.1 tops out at 9.2 and NOD32 at 7.2.
    it "reaches the documented maxima at CDP:H/TD:H" do
      parse("(AV:R/AC:L/Au:NR/C:P/I:P/A:C/B:A/E:F/RL:O/RC:C/CDP:H/TD:H)")
        .environmental_score.should eq(8.5)
      parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N/E:F/RL:O/RC:C/CDP:H/TD:H)")
        .environmental_score.should eq(9.2)
      parse("(AV:L/AC:H/Au:NR/C:C/I:C/A:C/B:N/E:P/RL:O/RC:C/CDP:H/TD:H)")
        .environmental_score.should eq(7.2)
    end

    it "reaches the documented minima at CDP:N/TD:N" do
      parse("(AV:R/AC:L/Au:NR/C:P/I:P/A:C/B:A/E:F/RL:O/RC:C/CDP:N/TD:N)")
        .environmental_score.should eq(0.0)
    end

    it "zeroes out on TD:N regardless of collateral damage" do
      parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N/CDP:H/TD:N)")
        .environmental_score.should eq(0.0)
    end
  end

  describe "severity" do
    it "uses the Low/Medium/High bands NVD applied to v1" do
      parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)").severity
        .should eq(CVSS::Severity::High)
      parse("(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)").severity
        .should eq(CVSS::Severity::Medium)
      parse("(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)").severity
        .should eq(CVSS::Severity::Low)
      parse("(AV:R/AC:L/Au:NR/C:N/I:N/A:N/B:N)").severity
        .should eq(CVSS::Severity::None)
    end

    it "never returns Critical" do
      parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)").severity
        .should_not eq(CVSS::Severity::Critical)
    end
  end

  describe "#to_s" do
    it "emits the parenthesised NVD notation" do
      parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)").to_s
        .should eq("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)")
    end

    it "canonicalises unparenthesised and prefixed input" do
      parse("AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N").to_s
        .should eq("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)")
      parse("CVSS:1.0/AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N").to_s
        .should eq("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)")
    end

    it "round-trips optional metrics in canonical order" do
      s = "(AV:L/AC:H/Au:R/C:N/I:P/A:C/B:C/E:F/RL:W/RC:Uc/CDP:M/TD:L)"
      parse(s).to_s.should eq(s)
    end

    it "normalises RC:UC to NVD's RC:Uc" do
      parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N/RC:UC)").to_s
        .should eq("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N/RC:Uc)")
    end
  end

  describe "#to_h" do
    it "exports base metrics and only the optional metrics that are set" do
      parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)").to_h.should eq({
        "AV" => "R", "AC" => "L", "Au" => "NR",
        "C" => "C", "I" => "C", "A" => "C", "B" => "N",
      })
      parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N/E:H/TD:L)").to_h.should eq({
        "AV" => "R", "AC" => "L", "Au" => "NR",
        "C" => "C", "I" => "C", "A" => "C", "B" => "N",
        "E" => "H", "TD" => "L",
      })
    end
  end

  describe "#metric_value" do
    it "returns codes for set metrics and ND for unset ones" do
      v = parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N/E:H)")
      v.metric_value("B").should eq("N")
      v.metric_value("E").should eq("H")
      v.metric_value("RL").should eq("ND")
      v.metric_value("TD").should eq("ND")
    end

    it "raises on an unknown metric key" do
      expect_raises(CVSS::Error, /unknown CVSS v1 metric/) do
        parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)").metric_value("PR")
      end
    end
  end

  describe "classification helpers" do
    it "reports access and impact characteristics" do
      v = parse("(AV:R/AC:L/Au:R/C:N/I:P/A:C/B:N)")
      v.remote?.should be_true
      v.network?.should be_true
      v.local?.should be_false
      v.requires_authentication?.should be_true
      v.impacts_confidentiality?.should be_false
      v.impacts_integrity?.should be_true
      v.impacts_availability?.should be_true
    end
  end

  describe "equality" do
    it "is structural and class-aware" do
      a = parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)")
      b = parse("AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N")
      a.should eq(b)
      a.hash.should eq(b.hash)

      # A v2 vector scoring 10.0 is never == a v1 vector scoring 10.0.
      a.should_not eq(CVSS.parse("AV:N/AC:L/Au:N/C:C/I:C/A:C"))
    end
  end

  describe "#to_json" do
    it "emits base fields" do
      json = JSON.parse(parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)").to_json)
      json["version"].should eq("1.0")
      json["vectorString"].should eq("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)")
      json["baseScore"].should eq(10.0)
      json["baseSeverity"].should eq("HIGH")
      json["temporalScore"]?.should be_nil
      json["environmentalScore"]?.should be_nil
    end

    it "adds temporal and environmental fields when those metrics are set" do
      json = JSON.parse(
        parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N/E:F/RL:O/RC:C/CDP:H/TD:H)").to_json)
      json["temporalScore"].should eq(8.3)
      json["temporalSeverity"].should eq("HIGH")
      json["environmentalScore"].should eq(9.2)
      json["environmentalSeverity"].should eq("HIGH")
    end
  end
end
