# Adding a new operating system release

The checklist for adding support for a new OS release (for example a new
Ubuntu LTS, EL major, or Debian stable). Work from the most similar existing
release and adjust for real differences.

## Key tenet: vanilla defaults only

The platform data in `data/os/` must reflect a **basic, vanilla install** of
the OS: exactly what the distribution ships in `/etc/ssh/ssh_config` and
`/etc/ssh/sshd_config`, nothing more. Never carry over settings from a
contributor's own systems, site policies, or hardening guides. This module's
defaults exist to reproduce the distribution's defaults, and users layer
their own choices on top via parameters and Hiera. Every value in the data
file must be traceable to the capture in step 1.

## 1. Capture the distribution defaults

Use the same container image the acceptance tests will use: the `image:` key
in the platform's nodeset under `spec/acceptance/nodesets/` (create the
nodeset first if needed, see step 6). Install the distribution's ssh packages
in that image and record what it ships.

Debian/Ubuntu example (image from `spec/acceptance/nodesets/debian-13.yml`):

```sh
docker run --rm debian:13 bash -c "apt-get update -qq >/dev/null && \
  DEBIAN_FRONTEND=noninteractive apt-get install -qq -y \
    openssh-client openssh-server >/dev/null && \
  echo '== ssh_config ==';  grep -vE '^#|^\$' /etc/ssh/ssh_config && \
  echo '== sshd_config =='; grep -vE '^#|^\$' /etc/ssh/sshd_config && \
  echo '== sftp-server ==';  ls /usr/lib/openssh/sftp-server && \
  echo '== service unit =='; ls /lib/systemd/system/ | grep -i ssh"
```

EL example (image from `spec/acceptance/nodesets/el10.yml`):

```sh
docker run --rm almalinux:10 bash -c "dnf install -q -y \
    openssh-clients openssh-server >/dev/null && \
  echo '== ssh_config ==';  grep -vE '^#|^\$' /etc/ssh/ssh_config && \
  echo '== sshd_config =='; grep -vE '^#|^\$' /etc/ssh/sshd_config && \
  echo '== drop-ins ==';    grep -rvE '^#|^\$' /etc/ssh/sshd_config.d/ && \
  echo '== sftp-server ==';  ls /usr/libexec/openssh/sftp-server && \
  echo '== service unit =='; ls /usr/lib/systemd/system/ | grep -i ssh"
```

Record: every uncommented directive in both files (and in any shipped
`ssh_config.d`/`sshd_config.d` drop-ins), the sftp-server path, the service
unit name (`ssh` vs `sshd`), and the include-directory conventions. Do not
assume the new release matches the previous one; verify.

## 2. Hiera data

Add `data/os/<OS>/<release>.yaml` mirroring the distribution defaults from
step 1. Optionally add a pristine capture to `spec/fixtures/untouched/` for
reference.

## 3. metadata.json

Add the release to the OS's `operatingsystemrelease` array. This is what puts
the platform into the unit test matrix (`actively_supported_os` reads it).

## 4. Spec coverage

In `spec/classes/init_spec.rb` and `spec/classes/server_spec.rb`:

- If the new release behaves identically to an existing one, widen that
  branch's regex (e.g. `%r{RedHat-(9|10)}`).
- If it differs (as EL10 did, splitting the server drop-in config into two
  files), add a dedicated `when` branch.

## 5. Test fixtures

Add `spec/fixtures/testing/<Platform>-<release>_ssh_config` and
`_sshd_config` containing the module's **exact rendered output** (start from
the nearest sibling's fixture; the templates emit spaces, never tabs). If the
platform declares `config_files`, add one fixture per drop-in file, named
`<Platform>-<release>_sshd_config.d_<name>`.

## 6. Acceptance

- Add `spec/acceptance/nodesets/<set>.yml` (copy the nearest sibling and
  change name, platform, image).
- Add the set to the acceptance matrix in `.github/workflows/ci.yaml`.

## 7. README

Add the release to the "Known to work" list.

## 8. Verify

```sh
bundle exec rake parallel_spec
```

- The total example count must **increase**; if it did not, facterdb has no
  facts for the release and the platform is being silently skipped; grep the
  output for "No facts were found".
- All examples pass and resource coverage stays at 100%.
- Run the CI validate chain, push, and confirm the new acceptance job passes;
  it is the only place the openvox-agent package for the new release gets
  exercised.
