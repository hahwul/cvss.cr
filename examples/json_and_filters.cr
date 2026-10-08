require "json"
require "../src/cvss"

# =============================================================================
# JSON Serialization, Classification Helpers, and Hash Export
# =============================================================================

puts "--- to_json (NVD-shaped) ---"
v3 = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C")
puts v3.to_json

puts "\n--- v4 to_json adds the macro vector ---"
v4 = CVSS.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
puts v4.to_json

puts "\n--- from_json: flat payload ---"
flat = %({"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
puts CVSS.from_json(flat).base_score # => 9.8

puts "\n--- from_json: NVD-nested payload ---"
nvd = <<-JSON
  {
    "source": "nvd@nist.gov",
    "type": "Primary",
    "cvssData": {
      "version": "3.1",
      "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "baseScore": 9.8,
      "baseSeverity": "CRITICAL"
    }
  }
  JSON
puts CVSS.from_json(nvd).severity # => Critical

puts "\n--- Reading a whole NVD API 2.0 response ---"
# The CVSS objects sit several levels down, and one CVE is commonly scored
# under more than one CVSS version. `from_json` takes the first;
# `from_json_all` takes them all.
nvd_response = <<-JSON
  {
    "vulnerabilities": [{
      "cve": {
        "id": "CVE-2021-44228",
        "metrics": {
          "cvssMetricV31": [{
            "source": "nvd@nist.gov",
            "cvssData": {
              "version": "3.1",
              "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
            }
          }],
          "cvssMetricV2": [{
            "source": "nvd@nist.gov",
            "cvssData": {
              "version": "2.0",
              "vectorString": "AV:N/AC:M/Au:N/C:P/I:P/A:P"
            }
          }]
        }
      }
    }]
  }
  JSON

CVSS.from_json_all(nvd_response).each do |vec|
  puts "  v#{vec.version}  #{vec.base_score}  #{vec.severity}  #{vec}"
end
worst = CVSS.from_json_all(nvd_response).max_by(&.base_score)
puts "Worst across versions: #{worst.base_score} (v#{worst.version})"

puts "\n--- Filtering with classification helpers ---"
# Known-good literals, so strict parse; for untrusted feeds use parse? and skip nils.
vulns = [
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", # network, no priv
  "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", # local, privileged
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", # XSS-style
  "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H", # physical
].map { |s| CVSS::V3::Vector.parse(s) }

puts "Network attacks needing no auth:"
vulns.select { |v| v.network? && !v.requires_privileges? }
  .each { |v| puts "  #{v.base_score}  #{v}" }

puts "\nVectors that change scope:"
vulns.select(&.scope_changed?)
  .each { |v| puts "  #{v}" }

puts "\nVectors with full CIA impact:"
vulns.select { |v| v.impacts_confidentiality? && v.impacts_integrity? && v.impacts_availability? }
  .each { |v| puts "  #{v.base_score}  #{v}" }

puts "\n--- to_h export ---"
puts v3.as(CVSS::V3::Vector).to_h

puts "\n--- Round-trip: Vector → JSON → Vector ---"
original = CVSS.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C")
roundtrip = CVSS.from_json(original.to_json)
puts "Equal? #{original == roundtrip}"
puts "Original:    #{original}"
puts "Round-trip:  #{roundtrip}"
