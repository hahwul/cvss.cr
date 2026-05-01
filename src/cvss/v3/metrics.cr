module CVSS::V3
  # ────────────────────────────────────────────────────────────
  # Base metrics (required in every CVSS v3.x vector)
  # ────────────────────────────────────────────────────────────

  enum AttackVector
    Network
    AdjacentNetwork
    Local
    Physical

    def self.parse(s : String) : AttackVector
      case s
      when "N" then Network
      when "A" then AdjacentNetwork
      when "L" then Local
      when "P" then Physical
      else          raise InvalidMetricError.new("invalid AV value: #{s}")
      end
    end

    def code : String
      case self
      in Network         then "N"
      in AdjacentNetwork then "A"
      in Local           then "L"
      in Physical        then "P"
      end
    end

    def weight : Float64
      case self
      in Network         then 0.85
      in AdjacentNetwork then 0.62
      in Local           then 0.55
      in Physical        then 0.20
      end
    end
  end

  enum AttackComplexity
    Low
    High

    def self.parse(s : String) : AttackComplexity
      case s
      when "L" then Low
      when "H" then High
      else          raise InvalidMetricError.new("invalid AC value: #{s}")
      end
    end

    def code : String
      self.low? ? "L" : "H"
    end

    def weight : Float64
      self.low? ? 0.77 : 0.44
    end
  end

  # PR's weight depends on Scope; resolve it via `weight(scope)`.
  enum PrivilegesRequired
    None
    Low
    High

    def self.parse(s : String) : PrivilegesRequired
      case s
      when "N" then None
      when "L" then Low
      when "H" then High
      else          raise InvalidMetricError.new("invalid PR value: #{s}")
      end
    end

    def code : String
      case self
      in None then "N"
      in Low  then "L"
      in High then "H"
      end
    end

    def weight(scope : Scope) : Float64
      if scope.changed?
        case self
        in None then 0.85
        in Low  then 0.68
        in High then 0.50
        end
      else
        case self
        in None then 0.85
        in Low  then 0.62
        in High then 0.27
        end
      end
    end
  end

  enum UserInteraction
    None
    Required

    def self.parse(s : String) : UserInteraction
      case s
      when "N" then None
      when "R" then Required
      else          raise InvalidMetricError.new("invalid UI value: #{s}")
      end
    end

    def code : String
      self.none? ? "N" : "R"
    end

    def weight : Float64
      self.none? ? 0.85 : 0.62
    end
  end

  enum Scope
    Unchanged
    Changed

    def self.parse(s : String) : Scope
      case s
      when "U" then Unchanged
      when "C" then Changed
      else          raise InvalidMetricError.new("invalid S value: #{s}")
      end
    end

    def code : String
      self.unchanged? ? "U" : "C"
    end
  end

  # CIA: Confidentiality / Integrity / Availability impact (same value table).
  enum Impact
    None
    Low
    High

    def self.parse(s : String) : Impact
      case s
      when "N" then None
      when "L" then Low
      when "H" then High
      else          raise InvalidMetricError.new("invalid CIA impact value: #{s}")
      end
    end

    def code : String
      case self
      in None then "N"
      in Low  then "L"
      in High then "H"
      end
    end

    def weight : Float64
      case self
      in None then 0.0
      in Low  then 0.22
      in High then 0.56
      end
    end
  end

  # ────────────────────────────────────────────────────────────
  # Temporal metrics (optional)
  # ────────────────────────────────────────────────────────────

  enum ExploitCodeMaturity
    NotDefined
    Unproven
    ProofOfConcept
    Functional
    High

    def self.parse(s : String) : ExploitCodeMaturity
      case s
      when "X" then NotDefined
      when "U" then Unproven
      when "P" then ProofOfConcept
      when "F" then Functional
      when "H" then High
      else          raise InvalidMetricError.new("invalid E value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined     then "X"
      in Unproven       then "U"
      in ProofOfConcept then "P"
      in Functional     then "F"
      in High           then "H"
      end
    end

    def weight : Float64
      case self
      in NotDefined     then 1.0
      in Unproven       then 0.91
      in ProofOfConcept then 0.94
      in Functional     then 0.97
      in High           then 1.0
      end
    end
  end

  enum RemediationLevel
    NotDefined
    OfficialFix
    TemporaryFix
    Workaround
    Unavailable

    def self.parse(s : String) : RemediationLevel
      case s
      when "X" then NotDefined
      when "O" then OfficialFix
      when "T" then TemporaryFix
      when "W" then Workaround
      when "U" then Unavailable
      else          raise InvalidMetricError.new("invalid RL value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined   then "X"
      in OfficialFix  then "O"
      in TemporaryFix then "T"
      in Workaround   then "W"
      in Unavailable  then "U"
      end
    end

    def weight : Float64
      case self
      in NotDefined   then 1.0
      in OfficialFix  then 0.95
      in TemporaryFix then 0.96
      in Workaround   then 0.97
      in Unavailable  then 1.0
      end
    end
  end

  enum ReportConfidence
    NotDefined
    Unknown
    Reasonable
    Confirmed

    def self.parse(s : String) : ReportConfidence
      case s
      when "X" then NotDefined
      when "U" then Unknown
      when "R" then Reasonable
      when "C" then Confirmed
      else          raise InvalidMetricError.new("invalid RC value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in Unknown    then "U"
      in Reasonable then "R"
      in Confirmed  then "C"
      end
    end

    def weight : Float64
      case self
      in NotDefined then 1.0
      in Unknown    then 0.92
      in Reasonable then 0.96
      in Confirmed  then 1.0
      end
    end
  end

  # ────────────────────────────────────────────────────────────
  # Environmental metrics (optional)
  # ────────────────────────────────────────────────────────────

  # Used by CR, IR, AR.
  enum SecurityRequirement
    NotDefined
    Low
    Medium
    High

    def self.parse(s : String) : SecurityRequirement
      case s
      when "X" then NotDefined
      when "L" then Low
      when "M" then Medium
      when "H" then High
      else          raise InvalidMetricError.new("invalid CR/IR/AR value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in Low        then "L"
      in Medium     then "M"
      in High       then "H"
      end
    end

    def weight : Float64
      case self
      in NotDefined then 1.0
      in Low        then 0.5
      in Medium     then 1.0
      in High       then 1.5
      end
    end
  end

  # Modified base metrics. `X` means "Not Defined" → fall back to the base
  # metric of the same family. Each modified type carries the same set of
  # legal codes as its base counterpart, plus `X`.

  enum ModifiedAttackVector
    NotDefined
    Network
    AdjacentNetwork
    Local
    Physical

    def self.parse(s : String) : ModifiedAttackVector
      case s
      when "X" then NotDefined
      when "N" then Network
      when "A" then AdjacentNetwork
      when "L" then Local
      when "P" then Physical
      else          raise InvalidMetricError.new("invalid MAV value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined      then "X"
      in Network         then "N"
      in AdjacentNetwork then "A"
      in Local           then "L"
      in Physical        then "P"
      end
    end

    def weight(base : AttackVector) : Float64
      case self
      in NotDefined      then base.weight
      in Network         then 0.85
      in AdjacentNetwork then 0.62
      in Local           then 0.55
      in Physical        then 0.20
      end
    end
  end

  enum ModifiedAttackComplexity
    NotDefined
    Low
    High

    def self.parse(s : String) : ModifiedAttackComplexity
      case s
      when "X" then NotDefined
      when "L" then Low
      when "H" then High
      else          raise InvalidMetricError.new("invalid MAC value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in Low        then "L"
      in High       then "H"
      end
    end

    def weight(base : AttackComplexity) : Float64
      case self
      in NotDefined then base.weight
      in Low        then 0.77
      in High       then 0.44
      end
    end
  end

  enum ModifiedPrivilegesRequired
    NotDefined
    None
    Low
    High

    def self.parse(s : String) : ModifiedPrivilegesRequired
      case s
      when "X" then NotDefined
      when "N" then None
      when "L" then Low
      when "H" then High
      else          raise InvalidMetricError.new("invalid MPR value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in None       then "N"
      in Low        then "L"
      in High       then "H"
      end
    end

    def weight(base : PrivilegesRequired, modified_scope : Scope) : Float64
      if self.not_defined?
        base.weight(modified_scope)
      else
        equivalent =
          case self
          in NotDefined then base
          in None       then PrivilegesRequired::None
          in Low        then PrivilegesRequired::Low
          in High       then PrivilegesRequired::High
          end
        equivalent.weight(modified_scope)
      end
    end
  end

  enum ModifiedUserInteraction
    NotDefined
    None
    Required

    def self.parse(s : String) : ModifiedUserInteraction
      case s
      when "X" then NotDefined
      when "N" then None
      when "R" then Required
      else          raise InvalidMetricError.new("invalid MUI value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in None       then "N"
      in Required   then "R"
      end
    end

    def weight(base : UserInteraction) : Float64
      case self
      in NotDefined then base.weight
      in None       then 0.85
      in Required   then 0.62
      end
    end
  end

  enum ModifiedScope
    NotDefined
    Unchanged
    Changed

    def self.parse(s : String) : ModifiedScope
      case s
      when "X" then NotDefined
      when "U" then Unchanged
      when "C" then Changed
      else          raise InvalidMetricError.new("invalid MS value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in Unchanged  then "U"
      in Changed    then "C"
      end
    end

    def effective(base : Scope) : Scope
      case self
      in NotDefined then base
      in Unchanged  then Scope::Unchanged
      in Changed    then Scope::Changed
      end
    end
  end

  enum ModifiedImpact
    NotDefined
    None
    Low
    High

    def self.parse(s : String) : ModifiedImpact
      case s
      when "X" then NotDefined
      when "N" then None
      when "L" then Low
      when "H" then High
      else          raise InvalidMetricError.new("invalid MC/MI/MA value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in None       then "N"
      in Low        then "L"
      in High       then "H"
      end
    end

    def weight(base : Impact) : Float64
      case self
      in NotDefined then base.weight
      in None       then 0.0
      in Low        then 0.22
      in High       then 0.56
      end
    end
  end
end
