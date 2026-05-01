require "../src/cvss"

# =============================================================================
# CVSS v2.0 Example
# =============================================================================
# CVSS v2 vectors have no "CVSS:x.y/" prefix. Severity is mapped using the
# legacy Low/Medium/High thresholds (no Critical band).

puts "--- Parsing & typed metric access ---"

v = CVSS::V2::Vector.parse("AV:N/AC:L/Au:N/C:P/I:P/A:P")
puts "Version:  #{v.version}"
puts "AV:       #{v.av}" # => Network
puts "AC:       #{v.ac}" # => Low
puts "Auth:     #{v.au}" # => None
puts "C/I/A:    #{v.c}/#{v.i}/#{v.a}"
puts "Score:    #{v.base_score}" # => 7.5
puts "Severity: #{v.severity}"   # => High

puts "\n--- Worst-case base ---"
worst = CVSS::V2::Vector.parse("AV:N/AC:L/Au:N/C:C/I:C/A:C")
puts "Vector: #{worst}"
puts "Score:  #{worst.base_score}" # => 10.0

puts "\n--- Temporal score with Functional / Official-Fix / Confirmed ---"
t = CVSS::V2::Vector.parse("AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C")
puts "Base:     #{t.base_score}"     # => 10.0
puts "Temporal: #{t.temporal_score}" # => 8.3

puts "\n--- Environmental score (CDP/TD/CR/IR/AR) ---"
e = CVSS::V2::Vector.parse(
  "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:LM/TD:H/CR:H/IR:M/AR:L"
)
puts "Vector:        #{e}"
puts "Environmental: #{e.environmental_score}"

puts "\n--- v2 severity bands (no Critical) ---"
[
  "AV:L/AC:H/Au:M/C:N/I:N/A:P", # Low
  "AV:N/AC:M/Au:S/C:P/I:P/A:N", # Medium
  "AV:N/AC:L/Au:N/C:C/I:C/A:C", # High
].each do |s|
  vec = CVSS::V2::Vector.parse(s)
  printf "%5.1f  %-7s  %s\n", vec.base_score, vec.severity, s
end
