require "../src/cvss"

# =============================================================================
# Error Handling
# =============================================================================
# Every error raised for a vector string inherits from CVSS::Error:
#   - CVSS::ParseError           — malformed / missing / duplicate metrics
#   - CVSS::InvalidMetricError   — value outside the metric's allowed set
#   - CVSS::UnknownVersionError  — unsupported "CVSS:x.y/" prefix
#
# Two things raise outside that hierarchy: CVSS.from_json raises
# JSON::ParseException when the input is not JSON at all (CVSS.from_json?
# swallows both and returns nil), and Severity.from_score raises
# ArgumentError for a NaN score.

def try_parse(label : String, input : String)
  CVSS.parse(input)
  puts "#{label}: ok (unexpected!)"
rescue err : CVSS::Error
  puts "#{label}: #{err.class.name.sub("CVSS::", "")} — #{err.message}"
end

puts "--- Each error class is reachable ---"

try_parse("missing base", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")
try_parse("duplicate", "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
try_parse("unknown metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:Y")
try_parse("bad value", "CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
try_parse("future version", "CVSS:5.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
try_parse("empty", "")

puts "\n--- Catching the parent class ---"

begin
  CVSS.parse("garbage")
rescue err : CVSS::Error
  puts "Caught at base class: #{err.class.name}"
end

puts "\n--- Distinguishing by subclass ---"

inputs = [
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",     # ParseError
  "CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", # InvalidMetricError
  "CVSS:9.9/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", # UnknownVersionError
]

inputs.each do |input|
  CVSS.parse(input)
rescue CVSS::UnknownVersionError
  puts "→ unsupported version prefix: #{input[0..14]}…"
rescue CVSS::InvalidMetricError
  puts "→ invalid metric value:        #{input}"
rescue CVSS::ParseError
  puts "→ malformed vector string:     #{input}"
end

puts "\n--- Non-raising forms ---"

puts "parse?(\"garbage\")                 => #{CVSS.parse?("garbage").inspect}"
puts "from_json?(\"not-json\")            => #{CVSS.from_json?("not-json").inspect}"
puts "from_json?(%({\"baseScore\": 9.8})) => #{CVSS.from_json?(%({"baseScore": 9.8})).inspect}"
puts "from_json?(valid payload)         => #{CVSS.from_json?(%({"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})).inspect}"
