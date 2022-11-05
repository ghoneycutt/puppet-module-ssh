# Release Process

1. Update metadata.json version, eg: `pdk bundle exec rake module:bump:{major,minor,patch}`
1. Run release task, eg: `pdk bundle exec rake release`
1. Update GitHub pages, eg: `pdk bundle exec rake strings:gh_pages:update`
1. Push to GitHub: `git push --tags origin main`
