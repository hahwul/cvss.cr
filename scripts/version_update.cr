# Shows the current version, prompts for a new one (blank keeps it), then
# writes it to every version-bearing marker. Keep the tracked list in sync
# with scripts/version_check.cr.
#
# Usage: crystal run scripts/version_update.cr  (just vu)
#
# NOT every version string in the repo belongs here. A marker is for text that
# means "the current release". Text stating WHEN something was introduced
# (CHANGELOG entries, "added in v0.2.0") is a historical fact that must stay put.
record Marker, path : String, pattern : Regex, replace : Proc(String, String), label : String? = nil do
  def name : String
    label ? "#{path} (#{label})" : path
  end
end

MARKERS = [
  Marker.new("shard.yml", /^version:\s*\S+/m, ->(v : String) { "version: #{v}" }),
  Marker.new("src/cvss/version.cr", /VERSION = "[^"]+"/, ->(v : String) { %(VERSION = "#{v}") }),
]

current = File.read("shard.yml").match(/^version:\s*(\S+)/m).try(&.[1]) || "unknown"
puts "Current version: #{current}"
print "New version (blank to keep): "
target = gets.try(&.strip) || ""

if target.empty?
  puts "No change."
  exit 0
end

unless target.matches?(/^\d+\.\d+\.\d+$/)
  STDERR.puts "✗ invalid version '#{target}' (expected X.Y.Z)"
  exit 1
end

# Verify EVERY marker before writing ANY: a half-applied bump leaves the tree in
# a state `just vc` rejects, and the operator has to work out which files got written.
MARKERS.each do |marker|
  next if File.read(marker.path).matches?(marker.pattern)
  STDERR.puts "✗ no version marker in #{marker.name}"
  exit 1
end

MARKERS.each do |marker|
  File.write(marker.path, File.read(marker.path).sub(marker.pattern, marker.replace.call(target)))
  puts "  ✓ #{marker.name}"
end

puts "✓ version: #{current} -> #{target}"
