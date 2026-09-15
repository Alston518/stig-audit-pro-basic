# Root Guard CDP Check Configuration

This guide explains exactly where to configure the automated Root Guard check for `V-220655`,
where to store approved core/distribution switch hostnames, and how site-profile inheritance
affects the result.

## Configuration map

| File | Purpose | What to configure |
|---|---|---|
| `data/checks/iosxe_l2.yaml` | Defines how `V-220655` collects and evaluates evidence | Normally leave this check alone after it has been installed |
| `data/profiles/base_iosxe_access.yaml` | Supplies settings shared by all inheriting sites | Put the complete organization-wide core/distribution hostname list here |
| `data/profiles/<site>.yaml` | Supplies settings unique to one site | Either inherit the base list or provide a complete replacement list |

## L2 check definition

The active check belongs in `data/checks/iosxe_l2.yaml`:

```yaml
- vuln_id: V-220655
  stig_id: CISC-L2-000090
  title: The Cisco switch must have Root Guard enabled on all switch ports connecting to access layer switches.
  stig_family: IOSXE_L2
  severity: cat3
  check_type: root_guard_neighbor_policy
  commands:
    - show running-config
    - show cdp neighbors detail
  automated: true
  scope: {}
  conditions:
    upstream_profile_key: root_guard.upstream_switches
    required_string: spanning-tree guard root
  result:
    pass_status: NotAFinding
    fail_status: Open
    error_status: Error
```

The settings have the following jobs:

| Setting | Meaning |
|---|---|
| `root_guard_neighbor_policy` | Activates the specialized CDP and Root Guard evaluator |
| `show running-config` | Collects interface configuration |
| `show cdp neighbors detail` | Identifies directly connected switches and their local interfaces |
| `upstream_profile_key` | Points to the profile list containing exempt upstream hostnames |
| `required_string` | Defines the required interface command for access-switch-facing links |

Do not put site-specific switch hostnames in the check definition. The check contains reusable
logic; profiles contain deployment-specific values.

## Organization-wide hostname list

When all site profiles can share one list, edit `data/profiles/base_iosxe_access.yaml`:

```yaml
root_guard:
  upstream_switches:
    - CORE-SW01
    - CORE-SW02
    - DIST-SW01
    - DIST-SW02
```

It is safe to list every possible core and distribution switch. An entry is used only when that
hostname appears as a direct CDP neighbor of the device being audited.

Use the hostname shown after `Device ID:` in `show cdp neighbors detail`:

```text
Device ID: CORE-SW01.example.mil
```

Either of these profile entries matches that neighbor:

```yaml
- CORE-SW01
- CORE-SW01.example.mil
```

Matching is case-insensitive, and a short hostname matches the equivalent FQDN.

## Site-specific profiles

A site profile such as `building_1.yaml` normally contains:

```yaml
profile_name: building_1
inherits: base_iosxe_access
```

If the site should use the organization-wide list, do not add a `root_guard` section to the site
profile. It will inherit the base list automatically.

If a site requires a different list, add a complete replacement:

```yaml
profile_name: building_1
inherits: base_iosxe_access

root_guard:
  upstream_switches:
    - BLDG1-CORE01
    - BLDG1-CORE02
    - BLDG1-DIST01
```

A site-specific `upstream_switches` list replaces the inherited base list; it does not append to
it. Every site override must therefore contain the complete set of approved upstream neighbors
for that site.

Do not leave a placeholder override in a site profile when the site should inherit from the base.
For example, remove the entire `root_guard` section from `example_site.yaml` if its placeholder
hostname is no longer needed.

## Evaluation behavior

The exemption applies per local interface, not to the entire device.

| CDP and configuration result | Status or action |
|---|---|
| Neighbor hostname is listed in `upstream_switches` | Exempt only that neighbor's local interface |
| Switch neighbor is not listed in `upstream_switches` | Treat it as an access-switch neighbor and inspect its local interface |
| Every access-switch-facing interface contains `spanning-tree guard root` | `NotAFinding` |
| Any access-switch-facing interface is missing Root Guard | `Open` |
| Only approved core/distribution switch neighbors are found | `Not_Applicable` |
| The upstream hostname list is empty | `Not_Reviewed` |
| No usable CDP neighbor entries are available | `Not_Reviewed` |
| The CDP neighbor is not a switch | Ignore it for this check |

For example:

```text
GigabitEthernet1/0/48 -> CORE-SW01
GigabitEthernet1/0/47 -> ACCESS-SW05
```

If `CORE-SW01` is listed in the profile, `GigabitEthernet1/0/48` is exempt. The separate link to
`ACCESS-SW05` must still contain:

```text
spanning-tree guard root
```

## Recommended configuration strategy

For the simplest maintenance model:

1. Maintain one complete organization-wide upstream list in `base_iosxe_access.yaml`.
2. Make every site profile inherit from `base_iosxe_access`.
3. Omit `root_guard` from site profiles unless a site genuinely requires a different list.
4. When a site overrides the list, enter its complete list rather than only the differences.
5. Confirm that CDP is enabled and that `show cdp neighbors detail` returns neighbor data during
   testing.

