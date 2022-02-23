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

  - To add a parameter for ssh_config related parameters you need to add it
    in alphabetical order to `manifest/init.pp` and `templates/ssh_config.erb`.
    Add tests to `spec/classes/init_params_spec.rb` that test that the
    new parameter will be added to the generated ssh_config as intended.
    To avoid accepting wrong data types add tests to
    `spec/classes/init_data_types_spec.rb` that test that only the intended
    data types will be accepted.

  - To add a parameter for sshd_config related parameters you need to add it
    in alphabetical order to `manifest/server.pp` and `templates/sshd_config.erb`.
    Add tests to `spec/classes/server_params_spec.rb` that test that the
    new parameter will be added to the generated ssh_config as intended.
    To avoid accepting wrong data types add tests to
    `spec/classes/server_data_types_spec.rb` that test that only the intended
    data types will be accepted.

  - To add support for a new operating system or updated version add a
    YAML data file to the structure to be found in `data/os/` and use the
    naming scheme `facts.os.name/facts.os.release.major`. Make sure
    that the configuration files are in the state the distributor delivered
    them and they are not touched by anyone. Set the parameters in a way
    that the resulting ssh_config / sshd_config will have the same parameters
    and values active like distributed. Use $custom to set parameters not
    featured by OpenSSH.
    Use one YAML file for each supported operating system. To make life
    easy, don't use inheritance instead set each parameter explicitly.
    Add the new operating system or updated version to `metadata.json`.
    This also activates testing of it.
    Add copies of the untouched ssh_config / sshd_config files to
    `spec/fixtures/untouched/`. Use the naming convention
    `facts.os.name-facts.os.release.major-ssh_config` and
    `facts.os.name-facts.os.release.major-sshd_config`.

  - If a new feature or parameter will change the default behaviour of the
    module make sure to add test to the corrosponding test file located
    in `spec/`.

  - Ensure that all test are running good :)


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
