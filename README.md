# svjpanel Home Assistant add-ons

Add this repository in Home Assistant: Settings > Add-ons > Add-on store > menu > Repositories:

    https://github.com/svjpanel/ha-addons

## Add-ons

- **svjpanel resident** (`svjpanel_resident`) - shares the entities and safe actions you select with your svjpanel account. Read the caveat for `script`/`scene`/`switch`/`input_boolean` actions in [DOCS.md](svjpanel_resident/DOCS.md) before enabling any.

The add-on is built locally by the Home Assistant Supervisor from a base image pinned by digest ([build.yaml](svjpanel_resident/build.yaml)); `config.yaml` has no `image:` key, so the GHCR images built by the release workflow are not consumed yet. Releases are exact version tags; `config.yaml` version changes only with a tagged release. Per-arch image digests are attached to each GitHub release as `release-digests.json`.

Before the first `v*` tag: repository write access (users, teams, installed GitHub Apps with `contents`/`workflows` write) must be Petr only, because any writer can push a branch workflow that overwrites the GHCR tag with `GITHUB_TOKEN`. If a second writer is added, move the GHCR push to a `release` environment secret with a required reviewer. Keep the tag ruleset (blocks tag moves/deletes). On the first tag run verify the digest read-back step passes.
