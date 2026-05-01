require "../src/cvss"

# =============================================================================
# Programmatic Vector Construction
# =============================================================================
# Vectors can be built directly from typed enum values without parsing a
# vector string first. Useful when generating vectors from form fields,
# scanner output, or templated data.

puts "--- v3.1 from typed enums ---"

v3 = CVSS::V3::Vector.new(
  av: CVSS::V3::AttackVector::Network,
  ac: CVSS::V3::AttackComplexity::Low,
  pr: CVSS::V3::PrivilegesRequired::None,
  ui: CVSS::V3::UserInteraction::None,
  s: CVSS::V3::Scope::Unchanged,
  c: CVSS::V3::Impact::High,
  i: CVSS::V3::Impact::High,
  a: CVSS::V3::Impact::High,
)
puts "to_s:  #{v3}" # => CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
puts "Score: #{v3.base_score}"

puts "\n--- v3 with temporal metrics ---"

v3t = CVSS::V3::Vector.new(
  av: CVSS::V3::AttackVector::Network,
  ac: CVSS::V3::AttackComplexity::Low,
  pr: CVSS::V3::PrivilegesRequired::None,
  ui: CVSS::V3::UserInteraction::None,
  s: CVSS::V3::Scope::Unchanged,
  c: CVSS::V3::Impact::High,
  i: CVSS::V3::Impact::High,
  a: CVSS::V3::Impact::High,
  e: CVSS::V3::ExploitCodeMaturity::Functional,
  rl: CVSS::V3::RemediationLevel::OfficialFix,
  rc: CVSS::V3::ReportConfidence::Confirmed,
)
puts "to_s:     #{v3t}"
puts "Temporal: #{v3t.temporal_score}"

puts "\n--- Pinning to v3.0 ---"

v30 = CVSS::V3::Vector.new(
  av: CVSS::V3::AttackVector::Network,
  ac: CVSS::V3::AttackComplexity::High,
  pr: CVSS::V3::PrivilegesRequired::None,
  ui: CVSS::V3::UserInteraction::None,
  s: CVSS::V3::Scope::Unchanged,
  c: CVSS::V3::Impact::High,
  i: CVSS::V3::Impact::High,
  a: CVSS::V3::Impact::High,
  version: "3.0",
)
puts "to_s:  #{v30}"
puts "Score: #{v30.base_score}"

puts "\n--- v2 ---"

v2 = CVSS::V2::Vector.new(
  av: CVSS::V2::AccessVector::Network,
  ac: CVSS::V2::AccessComplexity::Low,
  au: CVSS::V2::Authentication::None,
  c: CVSS::V2::Impact::Partial,
  i: CVSS::V2::Impact::Partial,
  a: CVSS::V2::Impact::Partial,
)
puts "to_s:  #{v2}" # => AV:N/AC:L/Au:N/C:P/I:P/A:P
puts "Score: #{v2.base_score}"

puts "\n--- v4 ---"

v4 = CVSS::V4::Vector.new(
  av: CVSS::V4::AttackVector::Network,
  ac: CVSS::V4::AttackComplexity::Low,
  at: CVSS::V4::AttackRequirements::None,
  pr: CVSS::V4::PrivilegesRequired::None,
  ui: CVSS::V4::UserInteraction::None,
  vc: CVSS::V4::VulnerableImpact::High,
  vi: CVSS::V4::VulnerableImpact::High,
  va: CVSS::V4::VulnerableImpact::High,
  sc: CVSS::V4::SubsequentImpact::None,
  si: CVSS::V4::SubsequentImpact::None,
  sa: CVSS::V4::SubsequentImpact::None,
)
puts "to_s:  #{v4}"
puts "Score: #{v4.base_score}"
