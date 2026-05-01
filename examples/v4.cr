require "../src/cvss"

# =============================================================================
# CVSS v4.0 Example
# =============================================================================
# CVSS v4.0 introduces Subsequent System impact (SC/SI/SA), Attack
# Requirements (AT), Threat metrics (E), and Supplemental metrics. Scoring is
# done via a 270-entry MacroVector lookup table plus a severity-distance
# correction.

puts "--- Base scoring ---"

v = CVSS::V4::Vector.parse(
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
)
puts "Vector:   #{v}"
puts "Score:    #{v.base_score}" # => 9.3
puts "Severity: #{v.severity}"

puts "\n--- The 6-character MacroVector ---"
puts "MacroVector: #{CVSS::V4::Score.macro_vector(v)}" # => 000200

puts "\n--- E:U downgrades the score (Unreported exploit) ---"

hi = CVSS::V4::Vector.parse(
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
)
lo = CVSS::V4::Vector.parse(
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U"
)
puts "E:X (default → A): #{hi.base_score}"
puts "E:U:               #{lo.base_score}"

puts "\n--- Modified base — environmental retargeting ---"
# Same vulnerability viewed in an environment where the attack vector is
# physical instead of network — score drops accordingly.
patched = CVSS::V4::Vector.parse(
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:P"
)
puts "Score with MAV:P:  #{patched.base_score}"

puts "\n--- All-impact-None shortcut ---"
zero = CVSS::V4::Vector.parse(
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
)
puts "Score: #{zero.base_score}  Severity: #{zero.severity}"

puts "\n--- Supplemental metrics are informational, do not affect score ---"

with_supp = CVSS::V4::Vector.parse(
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" \
  "/S:P/AU:Y/R:I/V:C/RE:H/U:Red"
)
puts "Score:        #{with_supp.base_score}" # same 9.3
puts "Urgency:      #{with_supp.u}"          # => Red
puts "Automatable:  #{with_supp.au}"         # => Yes
puts "Recovery:     #{with_supp.r}"          # => Irrecoverable
