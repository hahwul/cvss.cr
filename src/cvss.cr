# A Crystal implementation of the Common Vulnerability Scoring System (CVSS).
# See: https://www.first.org/cvss/
#
# Supported versions: v2.0, v3.0, v3.1, v4.0.
require "./cvss/version"
require "./cvss/error"
require "./cvss/severity"
require "./cvss/vector"
require "./cvss/v2/metrics"
require "./cvss/v2/vector"
require "./cvss/v3/metrics"
require "./cvss/v3/vector"
require "./cvss/v4/metrics"
require "./cvss/v4/macro_vector"
require "./cvss/v4/vector"
require "./cvss/parser"
require "./cvss/json"

module CVSS
  # Parse a CVSS vector string of any supported version.
  #
  # ```
  # CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").base_score # => 9.8
  # CVSS.parse("AV:N/AC:L/Au:N/C:P/I:P/A:P").base_score                   # => 7.5
  # ```
  def self.parse(input : String) : Vector
    Parser.parse(input)
  end

  # Non-raising parse — returns nil if the input is malformed or its CVSS
  # version is unsupported.
  #
  # ```
  # CVSS.parse?("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").try(&.base_score) # => 9.8
  # CVSS.parse?("garbage")                                                        # => nil
  # ```
  def self.parse?(input : String) : Vector?
    parse(input)
  rescue Error
    nil
  end
end
