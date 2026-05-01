require "../src/cvss"

# =============================================================================
# Error Handling
# =============================================================================
# All exceptions inherit from CVSS::Error:
#   - CVSS::ParseError           — malformed / missing / duplicate metrics
#   - CVSS::InvalidMetricError   — value outside the metric's allowed set
#   - CVSS::UnknownVersionError  — unsupported "CVSS:x.y/" prefix

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
  begin
    CVSS.parse(input)
  rescue CVSS::UnknownVersionError
    puts "→ unsupported version prefix: #{input[0..14]}…"
  rescue CVSS::InvalidMetricError
    puts "→ invalid metric value:        #{input}"
  rescue CVSS::ParseError
    puts "→ malformed vector string:     #{input}"
  end
end
