# Verifies that every version-bearing marker in the repo agrees.
# Keep the tracked list in sync with scripts/version_update.cr.
#
# Usage: crystal run scripts/version_check.cr  (just vc)
record Marker, path : String, pattern : Regex, label : String? = nil do
  def name : String
    label ? "#{path} (#{label})" : path
  end
end

MARKERS = [
  Marker.new("shard.yml", /^version:\s*(\S+)/m),
  Marker.new("src/cvss/version.cr", /VERSION = "([^"]+)"/),
]

# Read each file ONCE — several markers may share a path.
sources = MARKERS.map(&.path).uniq!.to_h { |path| {path, File.read(path)} }

width = MARKERS.max_of(&.name.size) + 2
found = MARKERS.map do |marker|
  version = sources[marker.path].match(marker.pattern).try(&.[1])
  puts "#{"#{marker.name}:".ljust(width)} #{version || "not found"}"
  {marker, version}
end

missing = found.select { |_, version| version.nil? }
unless missing.empty?
  STDERR.puts "✗ version not found in: #{missing.map(&.[0].name).join(", ")}"
  exit 1
end

unique = found.compact_map(&.[1]).uniq!
if unique.size > 1
  STDERR.puts "✗ version mismatch: #{unique.join(", ")}"
  exit 1
end

puts "✓ versions match (#{unique.first})"
