module CVSS::V2
  # ────────────────────────────────────────────────────────────
  # Base metrics
  # ────────────────────────────────────────────────────────────

  enum AccessVector
    Local
    AdjacentNetwork
    Network

    def self.parse(s : String) : AccessVector
      case s
      when "L" then Local
      when "A" then AdjacentNetwork
      when "N" then Network
      else          raise InvalidMetricError.new("invalid AV value: #{s}")
      end
    end

    def code : String
      case self
      in Local           then "L"
      in AdjacentNetwork then "A"
      in Network         then "N"
      end
    end

    def weight : Float64
      case self
      in Local           then 0.395
      in AdjacentNetwork then 0.646
      in Network         then 1.0
      end
    end
  end

  enum AccessComplexity
    High
    Medium
    Low

    def self.parse(s : String) : AccessComplexity
      case s
      when "H" then High
      when "M" then Medium
      when "L" then Low
      else          raise InvalidMetricError.new("invalid AC value: #{s}")
      end
    end

    def code : String
      case self
      in High   then "H"
      in Medium then "M"
      in Low    then "L"
      end
    end

    def weight : Float64
      case self
      in High   then 0.35
      in Medium then 0.61
      in Low    then 0.71
      end
    end
  end

  enum Authentication
    Multiple
    Single
    None

    def self.parse(s : String) : Authentication
      case s
      when "M" then Multiple
      when "S" then Single
      when "N" then None
      else          raise InvalidMetricError.new("invalid Au value: #{s}")
      end
    end

    def code : String
      case self
      in Multiple then "M"
      in Single   then "S"
      in None     then "N"
      end
    end

    def weight : Float64
      case self
      in Multiple then 0.45
      in Single   then 0.56
      in None     then 0.704
      end
    end
  end

  # CIA impact (same scale for C / I / A in v2.0).
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
      in Partial  then 0.275
      in Complete then 0.660
      end
    end
  end

  # ────────────────────────────────────────────────────────────
  # Temporal metrics (optional)
  # ────────────────────────────────────────────────────────────

  enum Exploitability
    Unproven
    ProofOfConcept
    Functional
    High
    NotDefined

    def self.parse(s : String) : Exploitability
      case s
      when "U"   then Unproven
      when "POC" then ProofOfConcept
      when "F"   then Functional
      when "H"   then High
      when "ND"  then NotDefined
      else            raise InvalidMetricError.new("invalid E value: #{s}")
      end
    end

    def code : String
      case self
      in Unproven       then "U"
      in ProofOfConcept then "POC"
      in Functional     then "F"
      in High           then "H"
      in NotDefined     then "ND"
      end
    end

    def weight : Float64
      case self
      in Unproven       then 0.85
      in ProofOfConcept then 0.9
      in Functional     then 0.95
      in High           then 1.0
      in NotDefined     then 1.0
      end
    end
  end

  enum RemediationLevel
    OfficialFix
    TemporaryFix
    Workaround
    Unavailable
    NotDefined

    def self.parse(s : String) : RemediationLevel
      case s
      when "OF" then OfficialFix
      when "TF" then TemporaryFix
      when "W"  then Workaround
      when "U"  then Unavailable
      when "ND" then NotDefined
      else           raise InvalidMetricError.new("invalid RL value: #{s}")
      end
    end

    def code : String
      case self
      in OfficialFix  then "OF"
      in TemporaryFix then "TF"
      in Workaround   then "W"
      in Unavailable  then "U"
      in NotDefined   then "ND"
      end
    end

    def weight : Float64
      case self
      in OfficialFix  then 0.87
      in TemporaryFix then 0.90
      in Workaround   then 0.95
      in Unavailable  then 1.0
      in NotDefined   then 1.0
      end
    end
  end

  enum ReportConfidence
    Unconfirmed
    Uncorroborated
    Confirmed
    NotDefined

    def self.parse(s : String) : ReportConfidence
      case s
      when "UC" then Unconfirmed
      when "UR" then Uncorroborated
      when "C"  then Confirmed
      when "ND" then NotDefined
      else           raise InvalidMetricError.new("invalid RC value: #{s}")
      end
    end

    def code : String
      case self
      in Unconfirmed    then "UC"
      in Uncorroborated then "UR"
      in Confirmed      then "C"
      in NotDefined     then "ND"
      end
    end

    def weight : Float64
      case self
      in Unconfirmed    then 0.90
      in Uncorroborated then 0.95
      in Confirmed      then 1.0
      in NotDefined     then 1.0
      end
    end
  end

  # ────────────────────────────────────────────────────────────
  # Environmental metrics (optional)
  # ────────────────────────────────────────────────────────────

  enum CollateralDamagePotential
    None
    Low
    LowMedium
    MediumHigh
    High
    NotDefined

    def self.parse(s : String) : CollateralDamagePotential
      case s
      when "N"  then None
      when "L"  then Low
      when "LM" then LowMedium
      when "MH" then MediumHigh
      when "H"  then High
      when "ND" then NotDefined
      else           raise InvalidMetricError.new("invalid CDP value: #{s}")
      end
    end

    def code : String
      case self
      in None       then "N"
      in Low        then "L"
      in LowMedium  then "LM"
      in MediumHigh then "MH"
      in High       then "H"
      in NotDefined then "ND"
      end
    end

    def weight : Float64
      case self
      in None       then 0.0
      in Low        then 0.1
      in LowMedium  then 0.3
      in MediumHigh then 0.4
      in High       then 0.5
      in NotDefined then 0.0
      end
    end
  end

  enum TargetDistribution
    None
    Low
    Medium
    High
    NotDefined

    def self.parse(s : String) : TargetDistribution
      case s
      when "N"  then None
      when "L"  then Low
      when "M"  then Medium
      when "H"  then High
      when "ND" then NotDefined
      else           raise InvalidMetricError.new("invalid TD value: #{s}")
      end
    end

    def code : String
      case self
      in None       then "N"
      in Low        then "L"
      in Medium     then "M"
      in High       then "H"
      in NotDefined then "ND"
      end
    end

    def weight : Float64
      case self
      in None       then 0.0
      in Low        then 0.25
      in Medium     then 0.75
      in High       then 1.0
      in NotDefined then 1.0
      end
    end
  end

  # CR / IR / AR
  enum SecurityRequirement
    Low
    Medium
    High
    NotDefined

    def self.parse(s : String) : SecurityRequirement
      case s
      when "L"  then Low
      when "M"  then Medium
      when "H"  then High
      when "ND" then NotDefined
      else           raise InvalidMetricError.new("invalid CR/IR/AR value: #{s}")
      end
    end

    def code : String
      case self
      in Low        then "L"
      in Medium     then "M"
      in High       then "H"
      in NotDefined then "ND"
      end
    end

    def weight : Float64
      case self
      in Low        then 0.5
      in Medium     then 1.0
      in High       then 1.51
      in NotDefined then 1.0
      end
    end
  end
end
