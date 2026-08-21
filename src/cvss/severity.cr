module CVSS
  # Qualitative severity rating used across CVSS v3.x and v4.0.
  # CVSS v2.0 ratings (Low/Medium/High) are mapped onto this enum
  # for a consistent API surface.
  enum Severity
    None
    Low
    Medium
    High
    Critical

    # Explicit override of `Enum#to_s : String`. The defaults *happen* to
    # match the member names, but defining both branches insulates the
    # public label from a future enum rename.
    def to_s : String
      case self
      in None     then "None"
      in Low      then "Low"
      in Medium   then "Medium"
      in High     then "High"
      in Critical then "Critical"
      end
    end

    def to_s(io : IO) : Nil
      io << to_s
    end

    # Maps a numeric base score (0.0..10.0) to a CVSS v3.x / v4.0 severity rating.
    def self.from_score(score : Float64) : Severity
      case score
      when .< 0.1 then None
      when .< 4.0 then Low
      when .< 7.0 then Medium
      when .< 9.0 then High
      else             Critical
      end
    end

    # CVSS v2.0 only defines Low/Medium/High. None is used for 0.0.
    def self.from_v2_score(score : Float64) : Severity
      case score
      when .< 0.1 then None
      when .< 4.0 then Low
      when .< 7.0 then Medium
      else             High
      end
    end

    # CVSS v1.0 defines no qualitative ratings at all. NVD nonetheless
    # labelled v1 scores while it published them, using the same
    # Low/Medium/High bands it later carried into v2.0 — so v1 reuses them.
    def self.from_v1_score(score : Float64) : Severity
      from_v2_score(score)
    end
  end
end
