# svjpanel resident

Shares the Home Assistant entities **you choose** with your svjpanel account, and lets svjpanel press the **safe actions you choose**. Private use only (a flat of your own); do not use it for business purposes.

## Setup

1. In the svjpanel portal open the Home Assistant page and create a pairing code.
2. Paste it into `pairing_code`, tick `t3_declaration` (you confirm you are entitled to share this Home Assistant), list the entities you want to read in `read_entities` and the actions in `actions`, then start the add-on.
3. The add-on log prints a 4-digit confirmation code chosen by svjpanel; type it in the portal to finish the pairing.
4. **After pairing, clear the `pairing_code` option.** It is single-use, but Home Assistant keeps it in the add-on options (and in backups) until you remove it.

Nothing is shared until you list it. There is no ingress and no open port; the add-on only makes outbound HTTPS calls to `ha-gateway.svjpanel.cz`.

## Read entities

Numbers and enums are sent by default. Text states need `text: true` (max 64 characters). Presence, power, energy, illuminance, CO2 and humidity sensors need `sensitive_ack: true` (they can reveal when you are home) and are sent at most once per 60 s.

## Actions

Only the services in the add-on allowlist can be used; `toggle`, camera, audio, location, lock, cover and alarm domains are not available in this version.

**Caveat for `script`, `scene`, `switch` and `input_boolean`:** such an entity can trigger other automations or devices in your Home Assistant that the add-on cannot see. Each needs `confirm_triggers_others: true`, which you set only if you accept that svjpanel users you authorize in the portal can run it.

## Security notes

- The add-on runs as root inside its container (no `USER`: `/data` is root-owned under Supervisor), with AppArmor enabled, no extra privileges, no open ports and no extra packages.
- It uses `homeassistant_api: true`, i.e. the Supervisor token with access to the **full Home Assistant API**. The only guard is the add-on's own policy (`policy.py`): it builds every call from your allowlisted `(entity, service)` pairs and rejects anything else. Code execution inside the add-on would therefore mean full access to your Home Assistant. Review the source in this repository before installing.
- Updates are built locally by the Supervisor from a base image pinned by digest; versions are immutable tags.

## Disconnect

"Disconnect" in the portal revokes the key; the add-on then stops. The key lives in the add-on's private `/data` (Home Assistant backups include it); remove it by uninstalling the add-on or disconnecting in the portal.
