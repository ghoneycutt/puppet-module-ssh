# Removing an end of life platform

The checklist for dropping a platform from active support when it reaches end
of life. The goal is to stop testing it, not to erase it.

## What is kept, always

- **`data/os/` files are never deleted.** Old platforms are known to keep
  working when their data is used, and that knowledge is not thrown away.
- The platform stays in the README "Known to work" list, which documents
  exactly this tier: untested, but functional via the retained data.

## 1. metadata.json

Remove the release from the OS's `operatingsystemrelease` array.

- Other releases remain: just drop the one entry.
- It was the last release: keep the OS entry but remove the whole
  `operatingsystemrelease` key. A versionless entry means known-to-work and
  is excluded from the test matrix by `actively_supported_os`
  (`spec/spec_helper_local.rb`).

## 2. Spec case branches

In `spec/classes/init_spec.rb` and `spec/classes/server_spec.rb`, narrow or
remove the platform's `when` branches. Two traps:

- A local variable assigned **only** in a removed branch (`packages_source`
  style) makes later references a `NameError`; replace such references with
  literal values.
- The OS-independent pinned blocks (`on_supported_os(redhat)` etc.) must not
  pin a removed release; facterdb may drop its facts, and the block will
  then silently run zero examples.

## 3. Test fixtures

Remove `spec/fixtures/testing/` files for the platform, and prune its entries
from `spec/fixtures/untouched/`.

## 4. Acceptance

Remove the nodeset from `spec/acceptance/nodesets/` and the entry from the
acceptance matrix in `.github/workflows/ci.yaml`.

## 5. Verify

```sh
bundle exec rake parallel_spec
```

- Expect the example count to **drop** by the removed platform's share, with
  0 failures.
- Resource coverage must stay at 100%; coverage filler assertions that lived
  only in removed contexts can leave resources untouched; the report names
  any offenders.
- Run the CI validate chain and push.
