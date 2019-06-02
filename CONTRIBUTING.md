# Contribution Guidelines

## Tests

  - Pull requests that add any additional functionality should have
    tests which cover the new feature to ensure it does what is
expected.

  - All platforms must have spec tests.

  - Only supported platforms will run functional tests with Beaker and
      Vagrant. Once a platform is end of life (EOL), it will no longer
      be supported and functional tests will be removed, though spec
      tests will remain.

  - Pull requests with failing tests will not be merged.

## Features

  - Keep feature based PRs as small as possible, with as few commits as
    necessary. These are easier to review and will be merged quicker.

## Bug Fixes

  - Make sure you reference the issue you're closing with `Fixes #<issue
    number>`.

## Commits

  - Squash/rebase any commits where possible to reduce the noise in the PR

## Git commits

Reference the issue number, in the format `(GH-###)`.

```
(GH-901) Add support for foo
```

# Release process

1. update version in `metadata.json`
1. run `github_changelog_generator`
1. update `CHANGELOG.md` and change `unreleased` at the top to the
   version, such as `v2.0.0`, and change `HEAD` to the same version,
   such as `v2.0.0`.
1. Update `REFERENCE.md` with the command `bundle exec rake reference`
1. Commit changes and push to master
1. Tag the new version, such as `git tag -a 'v2.0.0' -m 'v2.0.0'`
1. Push tags `git push --tags`
1. Update the puppet strings documentation with `bundle exec rake strings:gh_pages:update`
1. Clean up tests with `bundle exec rake spec_clean`
1. Remove junit directory from beaker runs `rm -fr junit`
1. Build module with `puppet module build`
1. Upload module to Puppet Forge.
