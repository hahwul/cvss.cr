require "./spec_helper"

# A trimmed but structurally faithful NVD API 2.0 response: the CVSS objects
# sit under `vulnerabilities[].cve.metrics.cvssMetricV3x[].cvssData`, several
# levels below where `from_json`'s flat lookups reach.
NVD_API_RESPONSE = <<-JSON
  {"resultsPerPage":1,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228","metrics":{
    "cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{
      "version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      "baseScore":10.0,"baseSeverity":"CRITICAL"}}],
    "cvssMetricV2":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{
      "version":"2.0","vectorString":"AV:N/AC:M/Au:N/C:P/I:P/A:P","baseScore":6.8}}]}}}]}
  JSON

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

    it "dispatches a parenthesised v1 vector on its Impact Bias metric" do
      vec = CVSS.parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)")
      vec.should be_a(CVSS::V1::Vector)
      vec.version.should eq("1.0")
      vec.base_score.should eq(10.0)
    end

    # NVD's v2.0 calculator renders v2 vectors parenthesised, exactly like
    # its v1 ones, so parentheses alone cannot mean "v1" — only the v1-only
    # Impact Bias metric can.
    it "dispatches a parenthesised vector without B to V2::Vector" do
      vec = CVSS.parse("(AV:N/AC:L/Au:N/C:P/I:P/A:P)")
      vec.should be_a(CVSS::V2::Vector)
      vec.version.should eq("2.0")
      vec.base_score.should eq(7.5)
      vec.to_s.should eq("AV:N/AC:L/Au:N/C:P/I:P/A:P")
    end

    it "dispatches a parenthesised v2 vector carrying optional metrics" do
      vec = CVSS.parse("(AV:N/AC:L/Au:N/C:P/I:P/A:P/E:F/RL:OF/RC:C)")
      vec.should eq(CVSS::V2::Vector.parse("AV:N/AC:L/Au:N/C:P/I:P/A:P/E:F/RL:OF/RC:C"))
    end

    it "accepts parentheses alongside an explicit CVSS:2.0/ prefix" do
      CVSS.parse("CVSS:2.0/(AV:N/AC:L/Au:N/C:P/I:P/A:P)").base_score.should eq(7.5)
    end

    # A truncated vector has lost the marker `Parser` dispatches on (for v1
    # that is `B`, at the tail), so the error names no version — only the
    # thing that is actually knowable about the input.
    it "reports a truncated vector as an unbalanced-parentheses error" do
      ["(AV:N/AC:L/Au:N/C:P/I:P/A:P", "(AV:R/AC:L/Au:NR/C:C/I:C/A:C"].each do |truncated|
        expect_raises(CVSS::ParseError, /unbalanced parentheses in vector string/) do
          CVSS.parse(truncated)
        end
      end
    end

    it "still detects v1 when B is the first metric inside the parentheses" do
      CVSS.parse("(B:N/AV:R/AC:L/Au:NR/C:C/I:C/A:C)").should be_a(CVSS::V1::Vector)
    end

    it "dispatches an unparenthesised v1 vector on its Impact Bias metric" do
      vec = CVSS.parse("AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N")
      vec.should be_a(CVSS::V1::Vector)
      vec.version.should eq("1.0")
    end

    it "dispatches an explicit CVSS:1.0/ prefix to V1::Vector" do
      vec = CVSS.parse("CVSS:1.0/(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)")
      vec.should be_a(CVSS::V1::Vector)
      vec.base_score.should eq(10.0)
    end

    it "reports a truncated v1 vector as a v1 parse error" do
      expect_raises(CVSS::ParseError, /unbalanced/) do
        CVSS.parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N")
      end
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

    it "accepts the CVSS: prefix in any case" do
      {
        "cvss:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"                    => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Cvss:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"                    => "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cVsS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" => "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "cvss:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"                             => "AV:N/AC:L/Au:N/C:P/I:P/A:P",
        "cvss:1.0/AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N"                        => "(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)",
      }.each do |input, canonical|
        CVSS.parse(input).to_s.should eq(canonical)
      end
    end

    it "keeps metric keys and values case-sensitive" do
      # Only the CVSS: prefix literal is case-insensitive — the specs write
      # metric keys and values in a fixed case and the parsers honour that.
      expect_raises(CVSS::ParseError, /unknown CVSS v3 metric 'av'/) do
        CVSS.parse("CVSS:3.1/av:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      end
      expect_raises(CVSS::InvalidMetricError, /invalid AV value: n/) do
        CVSS.parse("CVSS:3.1/AV:n/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      end
    end

    it "reports a prefix-less v3.x vector instead of misreading it as v2" do
      expect_raises(CVSS::ParseError, /CVSS v3.x metrics but no 'CVSS:3.0\/' or 'CVSS:3.1\/' prefix/) do
        CVSS.parse("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      end
    end

    it "reports a prefix-less v4.0 vector instead of misreading it as v2" do
      expect_raises(CVSS::ParseError, /CVSS v4.0 metrics but no 'CVSS:4.0\/' prefix/) do
        CVSS.parse("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
      end
    end

    it "still routes genuine prefix-less v1/v2 vectors" do
      # The v3/v4 detection keys off metrics no v1 or v2 vector can carry,
      # so the notations that legitimately omit a prefix are untouched.
      CVSS.parse("AV:N/AC:L/Au:N/C:P/I:P/A:P").should be_a(CVSS::V2::Vector)
      CVSS.parse("AV:N/AC:L/Au:N/C:P/I:P/A:P/E:POC/RL:OF/RC:C/CDP:MH/TD:H/CR:H/IR:M/AR:L")
        .should be_a(CVSS::V2::Vector)
      CVSS.parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)").should be_a(CVSS::V1::Vector)
    end

    it "names the version mismatch when a parser is handed another version's prefix" do
      expect_raises(CVSS::ParseError, /expected CVSS:2.0 prefix, got CVSS:3.1/) do
        CVSS::V2::Vector.parse("CVSS:3.1/AV:N/AC:L/Au:N/C:P/I:P/A:P")
      end
      expect_raises(CVSS::ParseError, /expected CVSS:4.0 prefix, got CVSS:3.1/) do
        CVSS::V4::Vector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      end
      expect_raises(CVSS::ParseError, /expected CVSS:1.0 prefix, got CVSS:2.0/) do
        CVSS::V1::Vector.parse("CVSS:2.0/AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N")
      end
    end

    it "raises on unknown CVSS version" do
      expect_raises(CVSS::UnknownVersionError) do
        CVSS.parse("CVSS:5.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      end
    end

    it "round-trips via to_s on every supported version" do
      [
        "(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)",
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

  describe "Cross-version accessors" do
    # Crystal resolves a method on an abstract type only when every subclass
    # answers it, so these compile at all only because all four vector
    # classes carry the whole family.
    it "answers the score family on a vector of unknown version" do
      [
        "(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N/E:U)",
        "AV:N/AC:L/Au:N/C:P/I:P/A:P/E:U",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
      ].each do |s|
        vec = CVSS.parse(s)
        vec.base_score.should be_a(Float64)
        vec.temporal_score.should be_a(Float64)
        vec.environmental_score.should be_a(Float64)
        vec.temporal_severity.should be_a(CVSS::Severity)
        vec.environmental_severity.should be_a(CVSS::Severity)
        vec.to_h.should be_a(Hash(String, String))
        vec.metric_value("AV").should be_a(String)
      end
    end

    it "aliases the v4.0 temporal accessors onto the Threat metric group" do
      vec = CVSS::V4::Vector.parse(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U")
      vec.temporal_score.should eq(vec.threat_score)
      vec.temporal_severity.should eq(vec.threat_severity)
    end

    it "reports unset optional metrics as the version's not-defined code" do
      CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").metric_value("E").should eq("X")
      CVSS.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        .metric_value("E").should eq("X")
      CVSS.parse("AV:N/AC:L/Au:N/C:P/I:P/A:P").metric_value("E").should eq("ND")
      CVSS.parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)").metric_value("E").should eq("ND")
    end

    it "distinguishes an unset metric from a set one via metric_code?" do
      vec = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X")
      # E:X is *set* — explicitly Not Defined — where RL is absent entirely.
      vec.metric_code?("E").should eq("X")
      vec.metric_code?("RL").should be_nil
      vec.metric_value("RL").should eq("X")
    end

    it "raises for a metric key the version does not define" do
      expect_raises(CVSS::Error, /unknown CVSS v3 metric 'AT'/) do
        CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").metric_value("AT")
      end
      expect_raises(CVSS::Error, /unknown CVSS v4 metric 'MS'/) do
        CVSS::V4::Vector.parse(
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").metric_value("MS")
      end
    end

    it "keeps to_h, to_s and metric_value in agreement" do
      [
        "(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:A/E:F/RL:O/RC:Uc/CDP:M/TD:H)",
        "AV:N/AC:L/Au:N/C:P/I:P/A:P/E:POC/RL:OF/RC:C/CDP:MH/TD:H/CR:H/IR:M/AR:L",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/MAV:P/MS:C",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/MSI:S/S:P/U:Red",
      ].each do |input|
        vec = CVSS.parse(input)
        h = vec.to_h
        h.each { |key, code| vec.metric_value(key).should eq(code) }
        # to_s emits exactly the metrics to_h reports, in the same order.
        h.map { |key, code| "#{key}:#{code}" }.join("/").should eq(
          vec.to_s.lchop("CVSS:#{vec.version}/").lchop('(').rchop(')'))
      end
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

    it "raises ParseError (not TypeCastError) when vectorString is non-string" do
      [
        %({"vectorString": 123}),
        %({"vectorString": null}),
        %({"vectorString": [1, 2, 3]}),
        %({"vectorString": {"x": 1}}),
        %({"vectorString": true}),
      ].each do |payload|
        expect_raises(CVSS::ParseError, /vectorString must be a string/) do
          CVSS.from_json(payload)
        end
      end
    end

    it "raises ParseError (not TypeCastError) when nested cvssData.vectorString is non-string" do
      expect_raises(CVSS::ParseError, /vectorString must be a string/) do
        CVSS.from_json(%({"cvssData": {"vectorString": 123}}))
      end
    end

    it "raises ParseError when the payload is valid JSON but not an object" do
      ["[1, 2, 3]", "null", %("hello"), "42", "true"].each do |payload|
        expect_raises(CVSS::ParseError, /JSON payload must be a JSON object/) do
          CVSS.from_json(payload)
        end
      end
    end

    it "raises ParseError when cvssData is not an object" do
      [%({"cvssData": "x"}), %({"cvssData": [1]}), %({"cvssData": null})].each do |payload|
        expect_raises(CVSS::ParseError, /cvssData must be a JSON object/) do
          CVSS.from_json(payload)
        end
      end
    end
  end

  describe "CVSS.from_json on nested payloads" do
    it "finds a vectorString buried in an NVD API 2.0 response" do
      vec = CVSS.from_json(NVD_API_RESPONSE)
      vec.should be_a(CVSS::V3::Vector)
      vec.base_score.should eq(10.0)
    end

    it "finds a vectorString in the legacy NVD 1.1 feed shape" do
      payload = <<-JSON
        {"impact":{"baseMetricV3":{"cvssV3":{
          "vectorString":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}}
        JSON
      CVSS.from_json(payload).base_score.should eq(9.8)
    end

    it "still prefers the flat and cvssData shapes over the deep walk" do
      CVSS.from_json(%({"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}))
        .should be_a(CVSS::V2::Vector)
      CVSS.from_json(%({"cvssData":{"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}}))
        .should be_a(CVSS::V2::Vector)
    end

    it "raises ParseError when no vectorString exists at any depth" do
      expect_raises(CVSS::ParseError, /no vectorString field/) do
        CVSS.from_json(%({"cve":{"id":"CVE-1999-0001","metrics":{}}}))
      end
    end

    it "raises ParseError for a non-string vectorString found by the walk" do
      expect_raises(CVSS::ParseError, /vectorString must be a string/) do
        CVSS.from_json(%({"metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":42}}]}}))
      end
    end
  end

  describe "CVSS.from_json_all" do
    it "returns every vector in a payload, in document order" do
      vectors = CVSS.from_json_all(NVD_API_RESPONSE)
      vectors.map(&.version).should eq(["3.1", "2.0"])
      vectors.map(&.base_score).should eq([10.0, 6.8])
      vectors.max_by(&.base_score).should be_a(CVSS::V3::Vector)
    end

    it "returns an empty array when the payload holds no vectorString" do
      CVSS.from_json_all(%({"vulnerabilities":[]})).should be_empty
      CVSS.from_json_all(%([1, 2, 3])).should be_empty
    end

    it "reads a flat single-vector payload too" do
      CVSS.from_json_all(%({"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}))
        .map(&.base_score).should eq([7.5])
    end

    it "raises when any vectorString in the payload is malformed" do
      expect_raises(CVSS::ParseError) do
        CVSS.from_json_all(%({"a":{"vectorString":"CVSS:3.1/AV:N"}}))
      end
    end

    it "raises UnknownVersionError for an unsupported version in the payload" do
      expect_raises(CVSS::UnknownVersionError) do
        CVSS.from_json_all(%({"a":{"vectorString":"CVSS:9.9/AV:N/AC:L"}}))
      end
    end
  end

  describe ".from_json?" do
    it "returns the parsed vector on success" do
      vec = CVSS.from_json?(%({"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}))
      vec.should_not be_nil
      vec.not_nil!.base_score.should eq(9.8)
    end

    it "returns nil for every shape from_json rejects" do
      [
        "not-json",                                     # JSON::ParseException
        "[1, 2, 3]",                                    # not an object
        %({"baseScore": 9.8}),                          # no vectorString
        %({"vectorString": 123}),                       # wrong type
        %({"vectorString": "CVSS:3.1/AV:N"}),           # unparsable vector
        %({"vectorString": "CVSS:5.0/AV:N/AC:L/PR:N"}), # unsupported version
      ].each do |payload|
        CVSS.from_json?(payload).should be_nil
      end
    end
  end

  describe "VectorString.strip_parens" do
    it "unwraps a balanced pair" do
      CVSS::VectorString.strip_parens("(AV:N/AC:L)").should eq("AV:N/AC:L")
    end

    it "leaves an unparenthesised body untouched" do
      CVSS::VectorString.strip_parens("AV:N/AC:L").should eq("AV:N/AC:L")
      CVSS::VectorString.strip_parens("").should eq("")
    end

    it "rejects a lone parenthesis on either end" do
      ["(AV:N", "AV:N)", "(", ")"].each do |body|
        expect_raises(CVSS::ParseError, /unbalanced parentheses/) do
          CVSS::VectorString.strip_parens(body)
        end
      end
    end

    # Peels exactly one level, and does not care that the result is empty —
    # judging the contents is `split_metrics`' job, not this one's.
    it "peels a single level and leaves the rest to split_metrics" do
      CVSS::VectorString.strip_parens("()").should eq("")
      CVSS::VectorString.strip_parens("((AV:N))").should eq("(AV:N)")
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

    # Binary floating point cannot represent these products exactly, so a
    # naive `(x * 10 + 0.5).floor` sees them as a hair *below* the .x5
    # boundary and rounds down. The spec arithmetic lands exactly on the
    # boundary and must round up — the same trap CVSS v3.1 §7.1 documents.
    it "rounds up products that binary arithmetic nudges below the boundary" do
      (3.0 * 0.95).should be < 2.85 # 2.8499999999999996
      CVSS.round1(3.0 * 0.95).should eq(2.9)

      (9.0 * 0.95).should be < 8.55 # 8.549999999999999
      CVSS.round1(9.0 * 0.95).should eq(8.6)

      CVSS.round1(2.85).should eq(2.9)
      CVSS.round1(8.35).should eq(8.4)
    end

    it "still rounds down when the value is genuinely below the boundary" do
      CVSS.round1(2.8499).should eq(2.8)
      CVSS.round1(2.84999).should eq(2.8)
    end

    # `round1` is public. The five-decimal snap goes through `to_i64`, which
    # raises OverflowError on non-finite input and on anything past
    # ~9.2233e13 (Int64::MAX / 100_000). No scoring path can reach those, but
    # a raw stdlib exception must never escape a public method.
    it "returns non-finite input unchanged instead of raising" do
      CVSS.round1(Float64::NAN).nan?.should be_true
      CVSS.round1(Float64::INFINITY).should eq(Float64::INFINITY)
      CVSS.round1(-Float64::INFINITY).should eq(-Float64::INFINITY)
    end

    it "falls back to the float path past the Int64 snap boundary" do
      [1.0e14, 9.3e13, -1.0e14, 1.0e300, -1.0e300, Float64::MAX].each do |x|
        CVSS.round1(x).should be_a(Float64)
      end
      CVSS.round1(1.0e300).should eq(1.0e300)
      CVSS.round1(1.0e14).should eq(1.0e14)
    end

    it "still snaps just inside the boundary" do
      CVSS.round1(CVSS::ROUND1_SNAP_LIMIT - 1.0).should be_a(Float64)
    end

    it "breaks ties upwards, not away from zero" do
      CVSS.round1(0.15).should eq(0.2)
      CVSS.round1(-0.15).should eq(-0.1)
      CVSS.round1(-0.16).should eq(-0.2)
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

    # Each band cutoff is on the *upper* boundary inclusive of the next band:
    # `< 0.1`, `< 4.0`, `< 7.0`, `< 9.0`. The boundary tests below pin those
    # cutoffs to catch any future `<` vs `<=` regression.
    it "uses < boundaries for v3/v4 severity bands" do
      CVSS::Severity.from_score(0.05).should eq(CVSS::Severity::None) # below 0.1
      CVSS::Severity.from_score(0.1).should eq(CVSS::Severity::Low)
      CVSS::Severity.from_score(3.99).should eq(CVSS::Severity::Low)
      CVSS::Severity.from_score(4.0).should eq(CVSS::Severity::Medium)
      CVSS::Severity.from_score(6.99).should eq(CVSS::Severity::Medium)
      CVSS::Severity.from_score(7.0).should eq(CVSS::Severity::High)
      CVSS::Severity.from_score(8.99).should eq(CVSS::Severity::High)
      CVSS::Severity.from_score(9.0).should eq(CVSS::Severity::Critical)
      CVSS::Severity.from_score(10.0).should eq(CVSS::Severity::Critical)
    end

    it "uses the legacy v2 banding (no Critical) at 7.0+" do
      CVSS::Severity.from_v2_score(0.0).should eq(CVSS::Severity::None)
      CVSS::Severity.from_v2_score(3.99).should eq(CVSS::Severity::Low)
      CVSS::Severity.from_v2_score(4.0).should eq(CVSS::Severity::Medium)
      CVSS::Severity.from_v2_score(6.99).should eq(CVSS::Severity::Medium)
      CVSS::Severity.from_v2_score(7.0).should eq(CVSS::Severity::High)
      CVSS::Severity.from_v2_score(10.0).should eq(CVSS::Severity::High)
    end

    # Every `<` against NaN is false, so an unguarded NaN would fall through
    # to the last band and be reported as Critical / High.
    it "rejects a NaN score instead of rating it as the worst band" do
      expect_raises(ArgumentError, /NaN/) { CVSS::Severity.from_score(Float64::NAN) }
      expect_raises(ArgumentError, /NaN/) { CVSS::Severity.from_v2_score(Float64::NAN) }
      expect_raises(ArgumentError, /NaN/) { CVSS::Severity.from_v1_score(Float64::NAN) }
    end

    it "saturates out-of-range scores at the nearest band" do
      CVSS::Severity.from_score(-1.0).should eq(CVSS::Severity::None)
      CVSS::Severity.from_score(99.0).should eq(CVSS::Severity::Critical)
    end

    it "is ordered: Critical > High > Medium > Low > None" do
      (CVSS::Severity::Critical > CVSS::Severity::High).should be_true
      (CVSS::Severity::High > CVSS::Severity::Medium).should be_true
      (CVSS::Severity::Medium > CVSS::Severity::Low).should be_true
      (CVSS::Severity::Low > CVSS::Severity::None).should be_true
    end
  end

  describe "Whitespace handling" do
    it "strips leading and trailing whitespace from any version" do
      CVSS.parse("  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  ").base_score.should eq(9.8)
      CVSS.parse("\nCVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N\t").base_score.should eq(9.3)
      CVSS.parse(" AV:N/AC:L/Au:N/C:P/I:P/A:P ").base_score.should eq(7.5)
    end

    it "rejects whitespace inside a metric value" do
      CVSS.parse?("CVSS:3.1/AV: N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").should be_nil
    end
  end

  describe "Round-trip via JSON across diverse vectors" do
    it "parse → to_json → from_json preserves the vector" do
      [
        # v2.0 base + temporal + environmental
        "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:LM/TD:H/CR:H/IR:M/AR:L",
        # v3.0 with optional metrics
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C",
        # v3.1 base only
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        # v3.1 environmental override
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:M/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:H/MI:N/MA:N",
        # v4.0 base
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        # v4.0 fully loaded
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/IR:H/AR:H/MAV:N/MSI:S/U:Red",
      ].each do |s|
        original = CVSS.parse(s)
        reconstructed = CVSS.from_json(original.to_json)
        reconstructed.should eq(original)
        reconstructed.to_s.should eq(original.to_s)
        reconstructed.base_score.should eq(original.base_score)
      end
    end
  end
end
