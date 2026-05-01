require "./spec_helper"

describe CVSS do
  it "exposes a version constant" do
    CVSS::VERSION.should be_a(String)
  end

  describe ".parse" do
    it "dispatches a v3.1 prefix to V3::Vector" do
      vec = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      vec.should be_a(CVSS::V3::Vector)
      vec.base_score.should eq(9.8)
      vec.version.should eq("3.1")
    end

    it "dispatches a v3.0 prefix to V3::Vector" do
      vec = CVSS.parse("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
      vec.should be_a(CVSS::V3::Vector)
      vec.version.should eq("3.0")
    end

    it "dispatches a v4.0 prefix to V4::Vector" do
      vec = CVSS.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
      vec.should be_a(CVSS::V4::Vector)
      vec.version.should eq("4.0")
      vec.base_score.should eq(9.3)
    end

    it "dispatches a prefix-less string to V2::Vector" do
      vec = CVSS.parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")
      vec.should be_a(CVSS::V2::Vector)
      vec.version.should eq("2.0")
      vec.base_score.should eq(7.5)
    end

    it "dispatches an explicit CVSS:2.0/ prefix to V2::Vector" do
      vec = CVSS.parse("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")
      vec.should be_a(CVSS::V2::Vector)
      vec.base_score.should eq(7.5)
    end

    it "raises on unknown CVSS version" do
      expect_raises(CVSS::UnknownVersionError) do
        CVSS.parse("CVSS:5.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      end
    end

    it "round-trips via to_s on every supported version" do
      [
        "AV:N/AC:L/Au:N/C:P/I:P/A:P",
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      ].each do |s|
        CVSS.parse(s).to_s.should eq(s)
      end
    end
  end

  describe ".parse?" do
    it "returns the parsed vector on success" do
      vec = CVSS.parse?("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      vec.should_not be_nil
      vec.not_nil!.base_score.should eq(9.8)
    end

    it "returns nil on malformed input" do
      CVSS.parse?("garbage").should be_nil
      CVSS.parse?("").should be_nil
      CVSS.parse?("CVSS:3.1/AV:N").should be_nil
    end

    it "returns nil for unsupported versions" do
      CVSS.parse?("CVSS:5.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").should be_nil
    end
  end

  describe "Equality + hash" do
    it "treats two structurally identical vectors as ==" do
      a = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      b = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      a.should eq(b)
      a.hash.should eq(b.hash)
    end

    it "distinguishes v3.0 from v3.1 even when metrics match" do
      a = CVSS.parse("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
      b = CVSS.parse("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
      a.should_not eq(b)
    end

    it "different versions with the same base score are not ==" do
      v2 = CVSS.parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")                   # 7.5
      v3 = CVSS.parse("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") # 7.8
      # These have different scores — but the test is about the rule:
      # cross-version comparison via == always returns false.
      v2.should_not eq(v3)
    end

    it "vectors are usable as Set / Hash keys" do
      set = Set(CVSS::Vector).new
      set << CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      set << CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      set.size.should eq(1)
    end
  end

  describe "Comparable" do
    it "sorts vectors by base score across versions" do
      vulns = [
        CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N"),                    # 0.0
        CVSS.parse("AV:N/AC:L/Au:N/C:C/I:C/A:C"),                                      # 10.0
        CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),                    # 9.8
        CVSS.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), # 9.3
      ]
      sorted = vulns.sort
      sorted.first.base_score.should eq(0.0)
      sorted.last.base_score.should eq(10.0)
    end

    it "supports < / > comparisons by score" do
      low = CVSS.parse("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N")
      high = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      (low < high).should be_true
      (high > low).should be_true
    end
  end

  describe "JSON serialization" do
    it "emits a NVD-shaped object for v3.1" do
      v = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      json = JSON.parse(v.to_json)
      json["version"].as_s.should eq("3.1")
      json["vectorString"].as_s.should eq(v.to_s)
      json["baseScore"].as_f.should eq(9.8)
      json["baseSeverity"].as_s.should eq("CRITICAL")
      json["exploitabilityScore"].as_f.should be_close(3.9, 0.05)
      json["impactScore"].as_f.should be_close(5.9, 0.05)
    end

    it "includes temporal fields only when temporal metrics are set" do
      bare = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      JSON.parse(bare.to_json)["temporalScore"]?.should be_nil

      with_temp = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C")
      json = JSON.parse(with_temp.to_json)
      json["temporalScore"].as_f.should eq(9.1)
      json["temporalSeverity"].as_s.should eq("CRITICAL")
    end

    it "includes environmental fields when env metrics are set (v3)" do
      v = CVSS.parse(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:M/MC:H/MI:N/MA:N"
      )
      json = JSON.parse(v.to_json)
      json["environmentalScore"]?.should_not be_nil
      json["environmentalSeverity"]?.should_not be_nil
    end

    it "includes temporal/environmental fields for v2 when set" do
      v = CVSS.parse("AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:LM/TD:H/CR:H/IR:M/AR:L")
      json = JSON.parse(v.to_json)
      json["temporalScore"].as_f.should eq(8.3)
      json["temporalSeverity"].as_s.should eq("HIGH")
      json["environmentalScore"].as_f.should eq(8.8)
      json["environmentalSeverity"].as_s.should eq("HIGH")
    end

    it "omits temporal/environmental for a bare v2 vector" do
      v = CVSS.parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")
      json = JSON.parse(v.to_json)
      json["temporalScore"]?.should be_nil
      json["environmentalScore"]?.should be_nil
    end

    it "emits the macro vector for v4" do
      v = CVSS.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
      json = JSON.parse(v.to_json)
      json["macroVector"].as_s.should eq("000200")
    end

    it "emits the spec §6 nomenclature for v4" do
      base = CVSS.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
      JSON.parse(base.to_json)["nomenclature"].as_s.should eq("CVSS-B")

      bte = CVSS.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/MAV:P")
      JSON.parse(bte.to_json)["nomenclature"].as_s.should eq("CVSS-BTE")
    end

    it "handles v2 vectors (no Critical band)" do
      v = CVSS.parse("AV:N/AC:L/Au:N/C:C/I:C/A:C")
      json = JSON.parse(v.to_json)
      json["version"].as_s.should eq("2.0")
      json["baseScore"].as_f.should eq(10.0)
      # v2 max severity is HIGH (no Critical band).
      json["baseSeverity"].as_s.should eq("HIGH")
    end
  end

  describe "CVSS.from_json" do
    it "reads a flat vectorString payload" do
      vec = CVSS.from_json(%({"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}))
      vec.base_score.should eq(9.8)
    end

    it "reads an NVD-nested cvssData.vectorString payload" do
      nvd = %({"cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}})
      vec = CVSS.from_json(nvd)
      vec.base_score.should eq(9.8)
    end

    it "ignores baseScore in the input and recomputes from vectorString" do
      # Tampered baseScore — we must trust the vectorString.
      tampered = %({"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 0.1})
      CVSS.from_json(tampered).base_score.should eq(9.8)
    end

    it "round-trips via to_json + from_json" do
      original = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C")
      reconstructed = CVSS.from_json(original.to_json)
      reconstructed.should eq(original)
    end

    it "raises ParseError when vectorString is missing" do
      expect_raises(CVSS::ParseError, /no vectorString/) do
        CVSS.from_json(%({"baseScore": 9.8}))
      end
    end

    it "propagates JSON::ParseException on malformed JSON" do
      expect_raises(JSON::ParseException) do
        CVSS.from_json("not-json")
      end
    end

    it "raises ParseError when vectorString itself is malformed" do
      expect_raises(CVSS::ParseError) do
        CVSS.from_json(%({"vectorString": "CVSS:3.1/AV:N"}))
      end
    end
  end

  describe "VectorString.split_metrics" do
    it "splits a well-formed body into ordered key/value pairs" do
      pairs = CVSS::VectorString.split_metrics("AV:N/AC:L/PR:N")
      pairs.should eq([{"AV", "N"}, {"AC", "L"}, {"PR", "N"}])
    end

    it "rejects an empty body" do
      expect_raises(CVSS::ParseError, /empty/) do
        CVSS::VectorString.split_metrics("")
      end
    end

    it "rejects a leading slash (empty first segment)" do
      expect_raises(CVSS::ParseError) do
        CVSS::VectorString.split_metrics("/AV:N/AC:L")
      end
    end

    it "rejects a trailing slash (empty last segment)" do
      expect_raises(CVSS::ParseError) do
        CVSS::VectorString.split_metrics("AV:N/AC:L/")
      end
    end

    it "rejects a segment without a colon" do
      expect_raises(CVSS::ParseError, /malformed/) do
        CVSS::VectorString.split_metrics("AV:N/justakey/AC:L")
      end
    end

    it "rejects a segment with an empty value" do
      expect_raises(CVSS::ParseError, /malformed/) do
        CVSS::VectorString.split_metrics("AV:N/AC:")
      end
    end
  end

  describe "CVSS.round1" do
    it "rounds half away from zero to one decimal place" do
      CVSS.round1(7.4499).should eq(7.4)
      CVSS.round1(7.45).should eq(7.5)
      CVSS.round1(7.4500001).should eq(7.5)
      CVSS.round1(0.0).should eq(0.0)
      CVSS.round1(10.0).should eq(10.0)
    end
  end

  describe "Severity" do
    it "maps numeric scores to qualitative ratings" do
      CVSS::Severity.from_score(0.0).should eq(CVSS::Severity::None)
      CVSS::Severity.from_score(3.9).should eq(CVSS::Severity::Low)
      CVSS::Severity.from_score(4.0).should eq(CVSS::Severity::Medium)
      CVSS::Severity.from_score(7.0).should eq(CVSS::Severity::High)
      CVSS::Severity.from_score(9.0).should eq(CVSS::Severity::Critical)
    end
  end
end
