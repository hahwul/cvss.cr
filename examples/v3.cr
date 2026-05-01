require "../src/cvss"

# =============================================================================
# CVSS v3.x Example
# =============================================================================
# CVSS::V3::Vector handles both v3.0 and v3.1 — they share metric definitions
# and only differ in the RoundUp algorithm used for the final score.

puts "--- Parsing & typed metric access ---"

v = CVSS::V3::Vector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
puts "Version:  #{v.version}"
puts "AV:       #{v.av}" # => Network
puts "AC:       #{v.ac}" # => Low
puts "Scope:    #{v.s}"  # => Unchanged
puts "C/I/A:    #{v.c}/#{v.i}/#{v.a}"

puts "\n--- Base / Temporal / Environmental scores ---"

vec = CVSS::V3::Vector.parse(
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"
)
puts "Base:          #{vec.base_score}"          # => 9.8
puts "Temporal:      #{vec.temporal_score}"      # => 9.1
puts "Environmental: #{vec.environmental_score}" # falls back to temporal when no env metrics

puts "\n--- Environmental override pulls the score down ---"

# Confidentiality requirement High but Modified Integrity / Availability:None
# means the score collapses around Confidentiality only.
env = CVSS::V3::Vector.parse(
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R" \
  "/CR:H/IR:H/AR:M/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:H/MI:N/MA:N"
)
puts "Base:          #{env.base_score}"          # => 9.8
puts "Environmental: #{env.environmental_score}" # => 6.3

puts "\n--- The same class handles v3.0 and v3.1 ---"
# v3.0 and v3.1 share metric definitions; only the RoundUp algorithm and the
# Modified Impact formula differ. The version is preserved on round-trip.
v30 = CVSS::V3::Vector.parse("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
v31 = CVSS::V3::Vector.parse("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
puts "v3.0 → #{v30}"
puts "v3.1 → #{v31}"
