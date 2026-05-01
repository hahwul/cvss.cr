module CVSS
  class Error < Exception
  end

  class ParseError < Error
  end

  class InvalidMetricError < Error
  end

  class UnknownVersionError < Error
  end
end
