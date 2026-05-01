require "./spec_helper"

# Reference scores cross-checked with the FIRST CVSS v2 calculator
# and the NIST Vulnerability Metrics page.
private def parse(s)
  CVSS::V2::Vector.parse(s)
end

describe CVSS::V2::Vector do
  describe ".parse" do
    it "parses a canonical v2 vector" do
      v = parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")
      v.version.should eq("2.0")
      v.av.should eq(CVSS::V2::AccessVector::Network)
      v.au.should eq(CVSS::V2::Authentication::None)
    end

    it "tolerates an explicit CVSS:2.0/ prefix" do
      parse("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P").base_score.should eq(7.5)
    end

    it "rejects missing base metrics" do
      expect_raises(CVSS::ParseError, /missing required/) do
        parse("AV:N/AC:L/Au:N/C:P/I:P")
      end
    end

    it "rejects bad values" do
      expect_raises(CVSS::InvalidMetricError) do
        parse("AV:Q/AC:L/Au:N/C:P/I:P/A:P")
      end
    end
  end

  describe "base_score" do
    it "scores 7.5 for AV:N/AC:L/Au:N/C:P/I:P/A:P" do
      parse("AV:N/AC:L/Au:N/C:P/I:P/A:P").base_score.should eq(7.5)
    end

    it "scores 10.0 for full network impact" do
      parse("AV:N/AC:L/Au:N/C:C/I:C/A:C").base_score.should eq(10.0)
    end

    it "scores 0.0 when there is no impact" do
      v = parse("AV:L/AC:H/Au:N/C:N/I:N/A:N")
      v.base_score.should eq(0.0)
      v.severity.should eq(CVSS::Severity::None)
    end

    it "scores 7.8 for network availability-only" do
      parse("AV:N/AC:L/Au:N/C:N/I:N/A:C").base_score.should eq(7.8)
    end

    it "maps medium severity correctly" do
      v = parse("AV:N/AC:M/Au:S/C:P/I:P/A:N")
      v.base_score.should eq(4.9)
      v.severity.should eq(CVSS::Severity::Medium)
    end
  end

  describe "temporal_score" do
    it "matches base when no temporal metrics are set" do
      v = parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")
      v.temporal_score.should eq(v.base_score)
    end

    it "applies E/RL/RC multipliers" do
      v = parse("AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C")
      # 10.0 * 0.95 * 0.87 * 1.0 = 8.265 → 8.3
      v.temporal_score.should eq(8.3)
    end
  end

  describe ".parse?" do
    it "returns nil on bad input" do
      CVSS::V2::Vector.parse?("AV:N/AC:L").should be_nil
    end
  end

  describe "Equality" do
    it "two parsed v2 vectors with the same string are ==" do
      a = parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")
      b = parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")
      a.should eq(b)
      a.hash.should eq(b.hash)
    end

    it "differs when an environmental metric differs" do
      a = parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")
      b = parse("AV:N/AC:L/Au:N/C:P/I:P/A:P/CDP:LM")
      a.should_not eq(b)
    end
  end

  describe "environmental_score" do
    it "computes the full CDP/TD/CR/IR/AR-aware score" do
      v = parse("AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:LM/TD:H/CR:H/IR:M/AR:L")
      v.environmental_score.should eq(8.8)
    end

    it "returns 0.0 when target distribution is None" do
      v = parse("AV:N/AC:L/Au:N/C:P/I:P/A:P/CDP:N/TD:N")
      v.environmental_score.should eq(0.0)
    end

    it "matches base score when no env metrics are set" do
      v = parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")
      v.environmental_score.should eq(v.base_score)
    end
  end

  describe "Classification helpers" do
    it "tags network / local / authentication" do
      net = parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")
      net.network?.should be_true
      net.requires_authentication?.should be_false

      auth = parse("AV:L/AC:L/Au:S/C:P/I:P/A:P")
      auth.local?.should be_true
      auth.requires_authentication?.should be_true
    end

    it "covers adjacent_network? and per-CIA impact" do
      adj = parse("AV:A/AC:L/Au:N/C:P/I:N/A:N")
      adj.adjacent_network?.should be_true
      adj.network?.should be_false
      adj.impacts_confidentiality?.should be_true
      adj.impacts_integrity?.should be_false
      adj.impacts_availability?.should be_false
    end
  end

  describe "to_h" do
    it "returns metric short-codes including the lowercase 'Au' key" do
      v = parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")
      v.to_h.should eq({
        "AV" => "N", "AC" => "L", "Au" => "N",
        "C" => "P", "I" => "P", "A" => "P",
      })
    end

    it "captures every temporal + environmental metric when set" do
      s = "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:LM/TD:H/CR:H/IR:M/AR:L"
      h = parse(s).to_h
      %w[E RL RC CDP TD CR IR AR].each do |k|
        h.has_key?(k).should be_true
      end
      h["CDP"].should eq("LM")
      h["RL"].should eq("OF")
    end
  end

  describe "to_s" do
    it "round-trips a base vector" do
      s = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
      parse(s).to_s.should eq(s)
    end

    it "round-trips with temporal+environmental" do
      s = "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:LM/TD:H/CR:H/IR:M/AR:L"
      parse(s).to_s.should eq(s)
    end
  end
end
