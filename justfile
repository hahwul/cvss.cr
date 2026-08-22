alias t := test
alias c := check
alias vc := version-check
alias vu := version-update

# List available tasks.
default:
    @just --list

# Run all tests.
[group('development')]
test:
    crystal spec

# Run one spec file (or dir), e.g. `just test-file spec/v3_spec.cr`.
[group('development')]
test-file path:
    crystal spec {{path}}

# Run every example as a smoke check (mirrors ci.yml's examples step).
[group('development')]
examples:
    #!/usr/bin/env bash
    set -euo pipefail
    for f in examples/*.cr; do
        echo "== $f"
        crystal run "$f"
    done

# Paths are explicit: bare `crystal tool format` walks the working directory and
# would reformat lib/ too — third-party code that is not ours to change.

# Check code format and lint without changing files.
[group('development')]
check:
    crystal tool format --check src spec examples scripts
    lib/ameba/bin/ameba.cr

# Auto-format code and fix lint issues.
[group('development')]
fix:
    crystal tool format src spec examples scripts
    lib/ameba/bin/ameba.cr --fix

# Check that every version-bearing file agrees: shard.yml and src/cvss/version.cr.
[group('version')]
version-check:
    crystal run scripts/version_check.cr

# Show the current version, then prompt for a new one (blank keeps it).
[group('version')]
version-update:
    crystal run scripts/version_update.cr

[group('documents')]
docs-serve:
    hwaro serve -i docs --base-url="http://localhost:3000"
