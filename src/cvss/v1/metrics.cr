module CVSS::V1
  # ────────────────────────────────────────────────────────────
  # Base metrics
  # ────────────────────────────────────────────────────────────

  enum AccessVector
    Local
    Remote

    def self.parse(s : String) : AccessVector
      case s
      when "L" then Local
      when "R" then Remote
      else          raise InvalidMetricError.new("invalid AV value: #{s}")
      end
    end

    def code : String
      case self
      in Local  then "L"
      in Remote then "R"
      end
    end

    def weight : Float64
      case self
      in Local  then 0.7
      in Remote then 1.0
      end
    end
  end

  enum AccessComplexity
    High
    Low

    def self.parse(s : String) : AccessComplexity
      case s
      when "H" then High
      when "L" then Low
      else          raise InvalidMetricError.new("invalid AC value: #{s}")
      end
    end

    def code : String
      case self
      in High then "H"
      in Low  then "L"
      end
    end

    def weight : Float64
      case self
      in High then 0.8
      in Low  then 1.0
      end
    end
  end

  # v1.0 authentication is binary: required or not. v2.0 later split the
  # "required" case into Single/Multiple.
  enum Authentication
    Required
    NotRequired

    def self.parse(s : String) : Authentication
      case s
      when "R"  then Required
      when "NR" then NotRequired
      else           raise InvalidMetricError.new("invalid Au value: #{s}")
      end
    end

    def code : String
      case self
      in Required    then "R"
      in NotRequired then "NR"
      end
    end

    def weight : Float64
      case self
      in Required    then 0.6
      in NotRequired then 1.0
      end
    end
  end

  # CIA impact (same scale for C / I / A in v1.0).
  enum Impact
    None
    Partial
    Complete

    def self.parse(s : String) : Impact
      case s
      when "N" then None
      when "P" then Partial
      when "C" then Complete
      else          raise InvalidMetricError.new("invalid CIA impact value: #{s}")
      end
    end

    def code : String
      case self
      in None     then "N"
      in Partial  then "P"
      in Complete then "C"
      end
    end

    def weight : Float64
      case self
      in None     then 0.0
      in Partial  then 0.7
      in Complete then 1.0
      end
    end
  end

  # Impact Bias — unique to CVSS v1.0. It re-weights the three impact
  # sub-scores relative to one another instead of contributing a single
  # weight of its own, so it exposes three accessors rather than `weight`.
  # v2.0 dropped the metric and moved this idea into the environmental
  # CR/IR/AR security requirements.
  enum ImpactBias
    Normal
    Confidentiality
    Integrity
    Availability

    def self.parse(s : String) : ImpactBias
      case s
      when "N" then Normal
      when "C" then Confidentiality
      when "I" then Integrity
      when "A" then Availability
      else          raise InvalidMetricError.new("invalid B value: #{s}")
      end
    end

    def code : String
      case self
      in Normal          then "N"
      in Confidentiality then "C"
      in Integrity       then "I"
      in Availability    then "A"
      end
    end

    # Weight applied to the Confidentiality impact.
    def conf_weight : Float64
      case self
      in Normal          then 0.333
      in Confidentiality then 0.5
      in Integrity       then 0.25
      in Availability    then 0.25
      end
    end

    # Weight applied to the Integrity impact.
    def integ_weight : Float64
      case self
      in Normal          then 0.333
      in Confidentiality then 0.25
      in Integrity       then 0.5
      in Availability    then 0.25
      end
    end

    # Weight applied to the Availability impact.
    def avail_weight : Float64
      case self
      in Normal          then 0.333
      in Confidentiality then 0.25
      in Integrity       then 0.25
      in Availability    then 0.5
      end
    end
  end

  # ────────────────────────────────────────────────────────────
  # Temporal metrics (optional)
  # ────────────────────────────────────────────────────────────
  #
  # Unlike v2.0+, CVSS v1.0 defines no "Not Defined" value for these. An
  # unset metric is represented as `nil` on the vector and scores as 1.0
  # (neutral), which is how the guide describes an unscored temporal group.

  enum Exploitability
    Unproven
    ProofOfConcept
    Functional
    High

    def self.parse(s : String) : Exploitability
      case s
      when "U" then Unproven
      when "P" then ProofOfConcept
      when "F" then Functional
      when "H" then High
      else          raise InvalidMetricError.new("invalid E value: #{s}")
      end
    end

    def code : String
      case self
      in Unproven       then "U"
      in ProofOfConcept then "P"
      in Functional     then "F"
      in High           then "H"
      end
    end

    def weight : Float64
      case self
      in Unproven       then 0.85
      in ProofOfConcept then 0.9
      in Functional     then 0.95
      in High           then 1.0
      end
    end
  end

  enum RemediationLevel
    OfficialFix
    TemporaryFix
    Workaround
    Unavailable

    def self.parse(s : String) : RemediationLevel
      case s
      when "O" then OfficialFix
      when "T" then TemporaryFix
      when "W" then Workaround
      when "U" then Unavailable
      else          raise InvalidMetricError.new("invalid RL value: #{s}")
      end
    end

    def code : String
      case self
      in OfficialFix  then "O"
      in TemporaryFix then "T"
      in Workaround   then "W"
      in Unavailable  then "U"
      end
    end

    # The worked examples in the v1 guide label Official-Fix as "(0.90)" in
    # their summary tables, but every arithmetic result printed alongside
    # them (7.00, 8.3, 4.4) only reproduces with 0.87 — the value the
    # normative formula section gives. The formula wins.
    def weight : Float64
      case self
      in OfficialFix  then 0.87
      in TemporaryFix then 0.90
      in Workaround   then 0.95
      in Unavailable  then 1.0
      end
    end
  end

  enum ReportConfidence
    Unconfirmed
    Uncorroborated
    Confirmed

    # NVD's v1 vector legend writes Uncorroborated as the mixed-case `Uc`.
    # Upper-case `UC` (the code v2.0 later assigned to *Unconfirmed*) shows
    # up in the wild too, so both spellings are accepted here; `code`
    # always emits NVD's `Uc`.
    def self.parse(s : String) : ReportConfidence
      case s
      when "U"        then Unconfirmed
      when "Uc", "UC" then Uncorroborated
      when "C"        then Confirmed
      else                 raise InvalidMetricError.new("invalid RC value: #{s}")
      end
    end

    def code : String
      case self
      in Unconfirmed    then "U"
      in Uncorroborated then "Uc"
      in Confirmed      then "C"
      end
    end

    def weight : Float64
      case self
      in Unconfirmed    then 0.90
      in Uncorroborated then 0.95
      in Confirmed      then 1.0
      end
    end
  end

  # ────────────────────────────────────────────────────────────
  # Environmental metrics (optional)
  # ────────────────────────────────────────────────────────────

  enum CollateralDamagePotential
    None
    Low
    Medium
    High

    def self.parse(s : String) : CollateralDamagePotential
      case s
      when "N" then None
      when "L" then Low
      when "M" then Medium
      when "H" then High
      else          raise InvalidMetricError.new("invalid CDP value: #{s}")
      end
    end

    def code : String
      case self
      in None   then "N"
      in Low    then "L"
      in Medium then "M"
      in High   then "H"
      end
    end

    def weight : Float64
      case self
      in None   then 0.0
      in Low    then 0.1
      in Medium then 0.3
      in High   then 0.5
      end
    end
  end

  enum TargetDistribution
    None
    Low
    Medium
    High

    def self.parse(s : String) : TargetDistribution
      case s
      when "N" then None
      when "L" then Low
      when "M" then Medium
      when "H" then High
      else          raise InvalidMetricError.new("invalid TD value: #{s}")
      end
    end

    def code : String
      case self
      in None   then "N"
      in Low    then "L"
      in Medium then "M"
      in High   then "H"
      end
    end

    def weight : Float64
      case self
      in None   then 0.0
      in Low    then 0.25
      in Medium then 0.75
      in High   then 1.0
      end
    end
  end
end
