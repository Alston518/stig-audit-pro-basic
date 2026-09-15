# Editing Check Strings and Site Variables

The check YAML files are the source of truth for what the app searches for today.
The GUI Checks tab can validate and save edits back to YAML. The Profiles tab can
validate and save profile YAML too.

Long term, the next friendlier step is a dedicated check-string editor so users
can edit `strings`, `required_strings`, and `forbidden_strings` without touching
raw YAML.

## Main Files

- `data/checks/iosxe_l2.yaml`: L2 STIG checks from the spreadsheet.
- `data/checks/iosxe_ndm.yaml`: NDM STIG checks from the spreadsheet.
- `data/profiles/*.yaml`: reusable values such as unused VLAN and required user VLAN lists.

Each check is intentionally short:

- `vuln_id`: the DISA `V-xxxxxx` number shown in Results and Reports.
- `stig_id`: the Cisco/STIG rule ID, such as `CISC-L2-000210`.
- `looking_for`: the short description from the spreadsheet.
- `commands`: the safe show commands the scan collects for that check.
- `conditions`: the strings, regex patterns, or profile variables used to decide pass/fail.

## Easy String Lists

For checks that look for literal text, edit the `strings` list.

```yaml
conditions:
  all:
    - command: show running-config
      strings:
        - spanning-tree loopguard default
```

You can add one string or several strings. Under `all`, every string must be present.

```yaml
strings:
  - first required command
  - second required command
```

For interface checks, edit `required_strings` or `forbidden_strings`.

```yaml
conditions:
  required_strings:
    - switchport block unicast
  forbidden_strings:
    - switchport mode dynamic
```

Blank string lists are allowed while a check is still being tailored. A check with no configured search strings returns `Not_Reviewed` instead of pretending to pass or fail.

```yaml
strings: []
```

## Regex Patterns

Some checks need regex because they are matching VLAN numbers, interface blocks, or "not this value" logic.

```yaml
pattern: ^switchport access vlan\s+{{ unused_vlan }}$
description: unused VLAN {{ unused_vlan }} assigned
```

Use `strings` for normal text searches. Use `pattern` only when the check needs flexible matching.

## Profile Variables

Profiles are where site values should live when the same check logic applies everywhere.

```yaml
unused_vlan: 999
dhcp_snooping:
  vlans:
    - 10
    - 20
    - 30
arp_inspection:
  vlans:
    - 10
    - 20
    - 30
```

Checks can reference profile values with double braces:

```yaml
pattern: ^switchport access vlan\s+{{ unused_vlan }}$
```

## Root Guard Neighbor Check

`V-220655` uses `show cdp neighbors detail` to identify directly connected switches. Core and
distribution neighbors are exempted by hostname. Every other switch-capable CDP neighbor is
treated as an access switch, and its local interface must contain `spanning-tree guard root`.

Store the exempt CDP `Device ID` hostnames in the selected site profile:

```yaml
root_guard:
  upstream_switches:
    - CORE-SW01
    - DIST-SW01
```

Short names match FQDNs, so `CORE-SW01` also matches `CORE-SW01.example.mil`. The exemption is
per interface: finding a core switch does not exempt a different interface connected to an access
switch. An empty hostname list or unavailable CDP neighbor data returns `Not_Reviewed`.

For profile lists, checks can expand one pattern per value:

```yaml
profile_all:
  - command: show running-config
    profile_key: dhcp_snooping.vlans
    object_type: vlan
    pattern_template: ^\s*ip dhcp snooping vlan\s+.*(?<!\d){{ item }}(?!\d).*$
    description_template: DHCP snooping VLAN {{ item }}
```

## Current Layout

L2 and NDM stay in separate files for now so each STIG can be maintained on its own. The app currently loads both libraries into one combined scan/report view. A later library selector or checkbox can make L2-only, NDM-only, or combined report/CKL runs explicit.

Current L2 status:

- 22 checks total.
- 19 automated string/pattern checks.
- 3 manual checks that return `Not_Reviewed`.

Current NDM status:

- 42 checks total.
- 33 editable string-search placeholders with blank `strings` lists.
- 1 automated ACL deny logging check.
- 8 manual or fixed-status entries for checks that still need better logic or were called out as N/A, NotAFinding, or Open in the spreadsheet.

## Testing One or More Checks From the Command Line

Copy complete check entries from `data/checks/iosxe_l2.yaml` into
`editing/check_test.yaml`, under `checks:`. Do not edit the production check file
until the test behaves as expected.

Run the copied checks against a live switch:

```powershell
python scripts/test_checks.py editing/check_test.yaml --host 10.0.0.10
```

The script prompts for the SSH username and password. Password input is hidden.
It only permits the read-only commands accepted by the application's command
planner. To use a different profile:

```powershell
python scripts/test_checks.py editing/check_test.yaml --host 10.0.0.10 --profile data/profiles/example_site.yaml
```

You can keep several checks in the test file and run selected IDs:

```powershell
python scripts/test_checks.py editing/check_test.yaml --host 10.0.0.10 --only V-220655 V-220657
```

For an offline test, place command output text files in a directory. Convert the
command to lowercase, replace spaces and punctuation with underscores, and add
`.txt`; for example, `show running-config` becomes
`show_running_config.txt`.

```powershell
python scripts/test_checks.py editing/check_test.yaml --outputs-dir tests/sample_outputs/compliant
```

Add `--json work/check-test-results.json` to save the complete result details.
The exit code is `0` when no result is Open or Error, `1` when a check is Open or
Error, and `2` for invalid YAML, missing output, unsafe commands, or SSH failure.
