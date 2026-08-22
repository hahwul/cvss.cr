# Contributing

Thanks for your interest in cvss.cr.

## Local development

```sh
shards install
crystal spec                # 227 examples
crystal tool format --check
```

Run an example end-to-end:

```sh
crystal run examples/basic.cr
```

With [just](https://github.com/casey/just) installed, the same tasks are
available as recipes (`just --list` shows them all):

```sh
just test          # crystal spec
just check         # format check + ameba
just fix           # format + ameba --fix
just examples      # run every examples/*.cr
```

## Releasing

Version numbers live in `shard.yml` and `src/cvss/version.cr`. Bump both at
once and verify they agree:

```sh
just version-update   # prompts for the new version, writes both files
just version-check    # fails if the two disagree
```

Then add the release section to `CHANGELOG.md` and tag the commit.

## Submitting changes

1. Fork the repository and create a branch.
2. Add or update specs under `spec/` for any code change.
3. Make sure `crystal spec` and `crystal tool format --check` pass — CI runs both.
4. Open a pull request describing the change and linking to the relevant CVSS spec section if applicable.

## Reporting issues

Please open an issue with:

- The CVSS vector string that triggers the problem.
- The expected score / severity (with a link to the FIRST calculator output if possible).
- The score / severity cvss.cr returned.

## Spec compliance

cvss.cr aims to match the official FIRST CVSS specifications:

- [v2.0](https://www.first.org/cvss/v2/guide)
- [v3.0](https://www.first.org/cvss/v3.0/specification-document) / [v3.1](https://www.first.org/cvss/v3.1/specification-document)
- [v4.0](https://www.first.org/cvss/v4.0/specification-document)

Bug reports referencing a specific section of these documents land fastest.
