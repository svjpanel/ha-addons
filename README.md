# svjpanel Home Assistant add-ons

Add this repository in Home Assistant: Settings > Add-ons > Add-on store > menu > Repositories:

    https://github.com/svjpanel/ha-addons

## Add-ons

- **svjpanel resident** (`svjpanel_resident`) - shares the entities and safe actions you select with your svjpanel account. Read the caveat for `script`/`scene`/`switch`/`input_boolean` actions in [DOCS.md](svjpanel_resident/DOCS.md) before enabling any.

The add-on is built locally by the Home Assistant Supervisor from a base image pinned by digest ([build.yaml](svjpanel_resident/build.yaml)). Releases are exact version tags; `config.yaml` version changes only with a tagged release.
