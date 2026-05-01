module CVSS
  # Round `x` to one decimal place, half-away-from-zero. Used by the v2 and
  # v3 score formulas (the v4 algorithm rounds inline). Centralised here so
  # the score module and the JSON serialiser cannot drift apart.
  def self.round1(x : Float64) : Float64
    ((x * 10.0 + 0.5).floor) / 10.0
  end

  # Common interface for every CVSS vector implementation.
  #
  # Each version (V2, V3, V4) implements its own subclass of this abstract
  # base. The shared API lets callers treat any parsed vector uniformly:
  #
  # ```
  # vec = CVSS.parse(input)
  # vec.base_score # => Float64
  # vec.severity   # => CVSS::Severity
  # vec.version    # => "3.1"
  # vec.to_s       # => canonical vector string
  # ```
  #
  # Vectors are `Comparable` by `base_score` — sort/compare across versions
  # by severity:
  #
  # ```
  # vulns = inputs.map { |s| CVSS.parse(s) }
  # vulns.sort.last # most severe
  # vulns.min       # least severe
  # ```
  #
  # Equality is *structural* and class-aware: two vectors are `==` only when
  # they are the same concrete class with identical metric values. A v3 and
  # v4 vector that happen to share a `base_score` are not `==`.
  abstract class Vector
    include Comparable(Vector)

    abstract def version : String
    abstract def base_score : Float64
    abstract def severity : Severity
    abstract def to_s(io : IO) : Nil

    # Order vectors by their base score. Subclasses do not need to override.
    # Returns nil only if a score is NaN, which never happens for valid
    # CVSS inputs — included for `Float64#<=>` compatibility.
    def <=>(other : Vector) : Int32?
      base_score <=> other.base_score
    end

    # Default cross-class equality: vectors of different concrete classes are
    # never `==`. Same-class subclasses override with field-level equality.
    # This also overrides the `==` that `Comparable` would otherwise derive
    # from `<=>` (we don't want score-equal vectors to compare equal).
    def ==(other : Vector) : Bool
      false
    end

    def to_s : String
      String.build { |io| to_s(io) }
    end

    def inspect(io : IO) : Nil
      io << "#<" << self.class.name << " "
      to_s(io)
      io << " base=" << base_score
      io << ">"
    end
  end

  # Splits a vector string body (the part after any "CVSS:x.y/" prefix) into
  # an ordered array of `{key, value}` tuples while validating shape.
  module VectorString
    extend self

    def split_metrics(body : String) : Array({String, String})
      raise ParseError.new("empty vector body") if body.empty?

      pairs = [] of {String, String}
      body.split('/').each do |segment|
        raise ParseError.new("empty metric segment") if segment.empty?
        key, _, value = segment.partition(':')
        if value.empty? || key.empty? || !segment.includes?(':')
          raise ParseError.new("malformed metric segment '#{segment}'")
        end
        pairs << {key, value}
      end
      pairs
    end
  end
end
