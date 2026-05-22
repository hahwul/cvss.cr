module CVSS::V4
  # ────────────────────────────────────────────────────────────
  # Base metrics (required)
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
      low? ? "L" : "H"
    end
  end

  enum AttackRequirements
    None
    Present

    def self.parse(s : String) : AttackRequirements
      case s
      when "N" then None
      when "P" then Present
      else          raise InvalidMetricError.new("invalid AT value: #{s}")
      end
    end

    def code : String
      none? ? "N" : "P"
    end
  end

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
  end

  enum UserInteraction
    None
    Passive
    Active

    def self.parse(s : String) : UserInteraction
      case s
      when "N" then None
      when "P" then Passive
      when "A" then Active
      else          raise InvalidMetricError.new("invalid UI value: #{s}")
      end
    end

    def code : String
      case self
      in None    then "N"
      in Passive then "P"
      in Active  then "A"
      end
    end
  end

  # Vulnerable system C/I/A impact
  enum VulnerableImpact
    High
    Low
    None

    def self.parse(s : String) : VulnerableImpact
      case s
      when "H" then High
      when "L" then Low
      when "N" then None
      else          raise InvalidMetricError.new("invalid VC/VI/VA value: #{s}")
      end
    end

    def code : String
      case self
      in High then "H"
      in Low  then "L"
      in None then "N"
      end
    end
  end

  # Subsequent system C/I/A impact (no Safety in base — only in modified MSI/MSA)
  enum SubsequentImpact
    High
    Low
    None

    def self.parse(s : String) : SubsequentImpact
      case s
      when "H" then High
      when "L" then Low
      when "N" then None
      else          raise InvalidMetricError.new("invalid SC/SI/SA value: #{s}")
      end
    end

    def code : String
      case self
      in High then "H"
      in Low  then "L"
      in None then "N"
      end
    end
  end

  # ────────────────────────────────────────────────────────────
  # Threat metric
  # ────────────────────────────────────────────────────────────

  enum ExploitMaturity
    NotDefined
    Attacked
    POC
    Unreported

    def self.parse(s : String) : ExploitMaturity
      case s
      when "X" then NotDefined
      when "A" then Attacked
      when "P" then POC
      when "U" then Unreported
      else          raise InvalidMetricError.new("invalid E value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in Attacked   then "A"
      in POC        then "P"
      in Unreported then "U"
      end
    end
  end

  # ────────────────────────────────────────────────────────────
  # Environmental — Security Requirements (CR/IR/AR)
  # ────────────────────────────────────────────────────────────

  enum SecurityRequirement
    NotDefined
    High
    Medium
    Low

    def self.parse(s : String) : SecurityRequirement
      case s
      when "X" then NotDefined
      when "H" then High
      when "M" then Medium
      when "L" then Low
      else          raise InvalidMetricError.new("invalid CR/IR/AR value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in High       then "H"
      in Medium     then "M"
      in Low        then "L"
      end
    end
  end

  # ────────────────────────────────────────────────────────────
  # Modified base metrics (each with X = NotDefined defaulting to base)
  # ────────────────────────────────────────────────────────────

  enum ModifiedAttackVector
    NotDefined; Network; AdjacentNetwork; Local; Physical

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
  end

  enum ModifiedAttackComplexity
    NotDefined; Low; High

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
  end

  enum ModifiedAttackRequirements
    NotDefined; None; Present

    def self.parse(s : String) : ModifiedAttackRequirements
      case s
      when "X" then NotDefined
      when "N" then None
      when "P" then Present
      else          raise InvalidMetricError.new("invalid MAT value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in None       then "N"
      in Present    then "P"
      end
    end
  end

  enum ModifiedPrivilegesRequired
    NotDefined; None; Low; High

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
  end

  enum ModifiedUserInteraction
    NotDefined; None; Passive; Active

    def self.parse(s : String) : ModifiedUserInteraction
      case s
      when "X" then NotDefined
      when "N" then None
      when "P" then Passive
      when "A" then Active
      else          raise InvalidMetricError.new("invalid MUI value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in None       then "N"
      in Passive    then "P"
      in Active     then "A"
      end
    end
  end

  enum ModifiedVulnerableImpact
    NotDefined; High; Low; None

    def self.parse(s : String) : ModifiedVulnerableImpact
      case s
      when "X" then NotDefined
      when "H" then High
      when "L" then Low
      when "N" then None
      else          raise InvalidMetricError.new("invalid MVC/MVI/MVA value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in High       then "H"
      in Low        then "L"
      in None       then "N"
      end
    end
  end

  enum ModifiedSubsequentConfidentiality
    NotDefined; High; Low; None

    def self.parse(s : String) : ModifiedSubsequentConfidentiality
      case s
      when "X" then NotDefined
      when "H" then High
      when "L" then Low
      when "N" then None
      else          raise InvalidMetricError.new("invalid MSC value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in High       then "H"
      in Low        then "L"
      in None       then "N"
      end
    end
  end

  # MSI/MSA add the Safety (S) value not present in base metrics.
  enum ModifiedSubsequentIntegrity
    NotDefined; Safety; High; Low; None

    def self.parse(s : String) : ModifiedSubsequentIntegrity
      case s
      when "X" then NotDefined
      when "S" then Safety
      when "H" then High
      when "L" then Low
      when "N" then None
      else          raise InvalidMetricError.new("invalid MSI value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in Safety     then "S"
      in High       then "H"
      in Low        then "L"
      in None       then "N"
      end
    end
  end

  enum ModifiedSubsequentAvailability
    NotDefined; Safety; High; Low; None

    def self.parse(s : String) : ModifiedSubsequentAvailability
      case s
      when "X" then NotDefined
      when "S" then Safety
      when "H" then High
      when "L" then Low
      when "N" then None
      else          raise InvalidMetricError.new("invalid MSA value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in Safety     then "S"
      in High       then "H"
      in Low        then "L"
      in None       then "N"
      end
    end
  end

  # ────────────────────────────────────────────────────────────
  # Supplemental metrics — informational only, do not affect score
  # ────────────────────────────────────────────────────────────

  enum Safety
    NotDefined; Negligible; Present

    def self.parse(s : String) : Safety
      case s
      when "X" then NotDefined
      when "N" then Negligible
      when "P" then Present
      else          raise InvalidMetricError.new("invalid S value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in Negligible then "N"
      in Present    then "P"
      end
    end
  end

  enum Automatable
    NotDefined; No; Yes

    def self.parse(s : String) : Automatable
      case s
      when "X" then NotDefined
      when "N" then No
      when "Y" then Yes
      else          raise InvalidMetricError.new("invalid AU value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in No         then "N"
      in Yes        then "Y"
      end
    end
  end

  enum Recovery
    NotDefined; Automatic; User; Irrecoverable

    def self.parse(s : String) : Recovery
      case s
      when "X" then NotDefined
      when "A" then Automatic
      when "U" then User
      when "I" then Irrecoverable
      else          raise InvalidMetricError.new("invalid R value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined    then "X"
      in Automatic     then "A"
      in User          then "U"
      in Irrecoverable then "I"
      end
    end
  end

  enum ValueDensity
    NotDefined; Diffuse; Concentrated

    def self.parse(s : String) : ValueDensity
      case s
      when "X" then NotDefined
      when "D" then Diffuse
      when "C" then Concentrated
      else          raise InvalidMetricError.new("invalid V value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined   then "X"
      in Diffuse      then "D"
      in Concentrated then "C"
      end
    end
  end

  enum ResponseEffort
    NotDefined; Low; Moderate; High

    def self.parse(s : String) : ResponseEffort
      case s
      when "X" then NotDefined
      when "L" then Low
      when "M" then Moderate
      when "H" then High
      else          raise InvalidMetricError.new("invalid RE value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in Low        then "L"
      in Moderate   then "M"
      in High       then "H"
      end
    end
  end

  enum ProviderUrgency
    NotDefined; Clear; Green; Amber; Red

    def self.parse(s : String) : ProviderUrgency
      case s
      when "X"     then NotDefined
      when "Clear" then Clear
      when "Green" then Green
      when "Amber" then Amber
      when "Red"   then Red
      else              raise InvalidMetricError.new("invalid U value: #{s}")
      end
    end

    def code : String
      case self
      in NotDefined then "X"
      in Clear      then "Clear"
      in Green      then "Green"
      in Amber      then "Amber"
      in Red        then "Red"
      end
    end
  end
end
