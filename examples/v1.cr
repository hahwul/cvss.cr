require "../src/cvss"

# =============================================================================
# CVSS v1.0 Example
# =============================================================================
# CVSS v1.0 (2005) predates the "CVSS:x.y/" prefix. The FIRST guide never
# standardised a vector string, so this library uses NVD's notation — the one
# every v1-era publisher adopted — which wraps the metric list in parentheses.
#
# Two things set v1.0 apart from every later version:
#   * Impact Bias (B), a base metric that re-weights C/I/A against each other.
#     v2.0 dropped it in favour of the environmental CR/IR/AR requirements.
#   * Binary Access Vector (Remote/Local) and Authentication (Required/Not).

puts "--- Parsing & typed metric access ---"

v = CVSS::V1::Vector.parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)")
puts "Version:  #{v.version}"
puts "AV:       #{v.av}" # => Remote
puts "AC:       #{v.ac}" # => Low
puts "Auth:     #{v.au}" # => NotRequired
puts "C/I/A:    #{v.c}/#{v.i}/#{v.a}"
puts "Bias:     #{v.b}"          # => Normal
puts "Score:    #{v.base_score}" # => 10.0
puts "Severity: #{v.severity}"   # => High

puts "\n--- Impact Bias re-weights the three impacts ---"
# Same vector, different bias: only Confidentiality is impacted, so biasing
# toward Confidentiality raises the score and biasing away lowers it.
%w[N C I A].each do |bias|
  vec = CVSS::V1::Vector.parse("(AV:R/AC:L/Au:NR/C:C/I:N/A:N/B:#{bias})")
  printf "B:%-1s  %5.1f  %s\n", bias, vec.base_score, vec.b
end

puts "\n--- Worked examples from the FIRST v1 guide (§3.1) ---"
{
  "CVE-2002-0392 (Apache chunked encoding)" => "(AV:R/AC:L/Au:NR/C:P/I:P/A:C/B:A/E:F/RL:O/RC:C)",
  "CAN-2003-0818 (Microsoft ASN.1)"         => "(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N/E:F/RL:O/RC:C)",
  "CVE-2003-0062 (NOD32 buffer overflow)"   => "(AV:L/AC:H/Au:NR/C:C/I:C/A:C/B:N/E:P/RL:O/RC:C)",
}.each do |name, s|
  vec = CVSS::V1::Vector.parse(s)
  printf "%-40s base=%4.1f  temporal=%4.1f\n", name, vec.base_score, vec.temporal_score
end

puts "\n--- Environmental score ---"
# CollateralDamagePotential can push the score up; TargetDistribution can only
# pull it down, all the way to 0.0 when the vulnerability affects no targets.
base = "(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N/E:F/RL:O/RC:C"
{"CDP:H/TD:H" => "worst case", "CDP:N/TD:M" => "partial rollout", "CDP:H/TD:N" => "no targets"}.each do |env, label|
  vec = CVSS::V1::Vector.parse("#{base}/#{env})")
  printf "%-12s  %4.1f  (%s)\n", env, vec.environmental_score, label
end

puts "\n--- Auto-detection & canonicalisation ---"
# CVSS.parse recognises v1 either by the parentheses or by the v1-only
# Impact Bias metric, and to_s always emits the canonical parenthesised form.
[
  "(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)",
  "AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N",
  "CVSS:1.0/AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N",
].each do |s|
  vec = CVSS.parse(s)
  printf "v%-3s  %5.1f  %-7s  %s\n", vec.version, vec.base_score, vec.severity, vec
end

puts "\n--- JSON ---"
puts CVSS::V1::Vector.parse("(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N/E:F/RL:O/RC:C)").to_json
