# AGENTS.md

Guidance for AI agents (and new contributors) working on this Puppet module.

## What this is

A Puppet module managing SSH client and server configuration. It runs on the
OpenVox / Vox Pupuli ecosystem, not Puppet Labs / Perforce tooling.

## Toolchain rules

- Use OpenVox and Vox Pupuli tooling, never the Puppet Labs equivalents:
  the `openvox` gem (selected via `PUPPET_GEM_VERSION`), `openfact`,
  `voxpupuli-test`, `voxpupuli-acceptance`, `voxpupuli-rubocop`,
  `openvox-strings`, `beaker_puppet_helpers`. The `puppet` and `facter`
  gems must never appear in `Gemfile.lock`.
- PDK is not used. Do not suggest `pdk update` or pdk-templates.
- Acceptance tests install `openvox-agent` from the Vox Pupuli repositories
  (`BEAKER_PUPPET_COLLECTION=openvox8`) into Docker containers defined by
  `spec/acceptance/nodesets/*.yml`.

## Commands

```sh
bundle install
bundle exec rake parallel_spec        # full unit suite, runs in under a minute
bundle exec rake check:git_ignore check:dot_underscore check:test_file \
  rubocop syntax lint metadata_lint   # the CI validate chain
BEAKER_set=el9 bundle exec rake beaker  # acceptance for one nodeset (needs Docker)
```

Use the same Ruby version CI uses; see `ruby-version` in
`.github/workflows/ci.yaml`. RVM is the suggested way to install and manage it.
A UTF-8 locale is required: `export LC_ALL=en_US.UTF-8` or `metadata_lint`
fails with an encoding error.

## Conventions

- **`data/os/` is permanent.** OS default data for end of life platforms is
  deliberately kept forever, even after the platform leaves the test matrix.
  Never delete files under `data/`.
- **`data/os/` holds vanilla distribution defaults only**: what a basic
  install of that OS ships in its ssh/sshd config, verified against the real
  distribution container, never a contributor's customized settings.
- **Platform support tiers**: an OS listed in `metadata.json` *with* an
  `operatingsystemrelease` array is actively supported and tested (the spec
  matrix is built from it via `actively_supported_os` in
  `spec/spec_helper_local.rb`). An OS listed *without* versions is
  known-to-work only: its data remains but nothing tests it. Archlinux is
  versionless because it is a rolling release, yet still tested (allowlisted).
- **`spec/fixtures/testing/`** files are byte-exact expected output of this
  module's templates, not distribution files. They must match rendered catalog
  content exactly (spacing included).
- **`spec/fixtures/untouched/`** files are pristine captures of distribution
  default configs, kept as reference only; no spec reads them.
- **RuboCop**: config is inherited from the `voxpupuli-rubocop` gem;
  pre-existing offenses are grandfathered in `.rubocop_todo.yml`. Never run
  mass autocorrects over existing code; style churn destroys git history and
  breaks open pull requests. New code must comply.
- **100% resource coverage is enforced** (`RSpec::Puppet::Coverage.report!(100)`).
  Every resource in any compiled catalog must be touched by an assertion; the
  suite uses "tests needed to reach 100% resource coverage" filler assertions
  where necessary.
- Pull requests are typically a single commit; amend rather than stacking
  fixup commits. Preserve original authorship when rebasing contributor
  commits and add co-authors via `Co-Authored-By` trailers.
- `voxpupuli-test` and `voxpupuli-rubocop` versions are pinned in lockstep
  (both pin the same rubocop line); bump them together.
- **ASCII only.** Never use em dashes, smart quotes, or other non-ASCII
  characters in any file in this repo; use plain ASCII punctuation instead.
  The one exception is spec/: multibyte strings used as test input vectors
  (for example the Japanese string in the type alias specs) are deliberate
  test data that verifies unicode handling, and must be kept.

## Gotchas learned the hard way

- If facterdb has no facts for a declared platform, `on_supported_os` yields
  nothing and that platform's tests are **silently skipped**. After adding or
  changing platforms, confirm the total example count went up and grep the
  spec output for "No facts were found".
- Local variables assigned only inside removed `when` branches cause
  `NameError` at spec load; check `packages_source`-style variables when
  editing the platform case statements.
- Fixture content mismatches are usually whitespace: the templates emit
  spaces, never tabs, and the client config `Include` line is indented two
  spaces.
- Verify a platform's default ssh/sshd settings against the real distribution
  container (the image named in its nodeset), not from memory.

## Common tasks

- [Adding a new operating system release](docs/adding-an-os-release.md)
- [Removing an end of life platform](docs/removing-an-eol-platform.md)
