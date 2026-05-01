require "../src/cvss"

# =============================================================================
# Basic Usage
# =============================================================================
# CVSS.parse(string) auto-detects the version from the "CVSS:x.y/" prefix.
# Strings without a prefix are treated as CVSS v2.0.

puts "--- Auto-detecting the version ---"

vec = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
puts "Vector:   #{vec}"
puts "Version:  #{vec.version}"    # => 3.1
puts "Score:    #{vec.base_score}" # => 9.8
puts "Severity: #{vec.severity}"   # => Critical

puts "\n--- Same API across every supported version ---"
[
  "AV:N/AC:L/Au:N/C:P/I:P/A:P",                                      # v2
  "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",                    # v3.0
  "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",                    # v3.1
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", # v4.0
].each do |s|
  v = CVSS.parse(s)
  printf "v%-3s  %5.1f  %-8s  %s\n", v.version, v.base_score, v.severity, s
end

puts "\n--- Round-tripping ---"
input = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"
parsed = CVSS.parse(input)
puts "Input:   #{input}"
puts "to_s:    #{parsed}"
puts "Match:   #{parsed.to_s == input}"

puts "\n--- Severity from arbitrary scores ---"
[0.0, 3.9, 4.0, 6.9, 7.0, 9.0, 10.0].each do |s|
  puts "#{s.round(1)} → #{CVSS::Severity.from_score(s)}"
end
