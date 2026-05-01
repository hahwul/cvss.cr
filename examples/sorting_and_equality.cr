require "../src/cvss"

# =============================================================================
# Equality, Hashing, Sorting, and Non-raising Parse
# =============================================================================

puts "--- parse? returns nil on bad input ---"
puts "good:    #{CVSS.parse?("AV:N/AC:L/Au:N/C:P/I:P/A:P").try(&.base_score)}"
puts "garbage: #{CVSS.parse?("garbage").inspect}"
puts "bad ver: #{CVSS.parse?("CVSS:9.9/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").inspect}"

puts "\n--- Structural equality + hashing ---"
a = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F")
b = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F")
c = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") # no E:F
puts "a == b: #{a == b}"
puts "a == c: #{a == c}" # different optional metrics
puts "hash(a) == hash(b): #{a.hash == b.hash}"

puts "\n--- Vectors as Set / Hash keys ---"
seen = Set(CVSS::Vector).new
%w[
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
].each { |s| seen << CVSS.parse(s) }
puts "Unique vectors: #{seen.size}"

puts "\n--- Sorting by severity (cross-version) ---"
vulns = [
  "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N",
  "AV:N/AC:L/Au:N/C:C/I:C/A:C",
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
  "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N",
].map { |s| CVSS.parse(s) }

puts "Sorted ascending by base_score:"
vulns.sort.each do |v|
  printf "  %5.1f  v%-3s  %s\n", v.base_score, v.version, v
end

puts "\nMost severe: #{vulns.max_by(&.base_score).base_score}"
puts "Least severe: #{vulns.min_by(&.base_score).base_score}"

puts "\n--- v3 sub-scores ---"
v3 = CVSS::V3::Vector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
puts "ISS:                     #{v3.iss.round(4)}"
puts "Impact subscore:         #{v3.impact_subscore.round(3)}"
puts "Exploitability subscore: #{v3.exploitability_subscore.round(3)}"
puts "Base score:              #{v3.base_score}"

puts "\n--- v4 macro vector accessor ---"
v4 = CVSS::V4::Vector.parse(
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
)
puts "Macro: #{v4.macro_vector}  Score: #{v4.base_score}"

# Same vulnerability seen with E:U (Unreported) shifts EQ5 from 0 to 2.
v4u = CVSS::V4::Vector.parse(
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U"
)
puts "With E:U  → Macro: #{v4u.macro_vector}  Score: #{v4u.base_score}"
