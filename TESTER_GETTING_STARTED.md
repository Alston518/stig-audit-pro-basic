# STIG Audit Pro - Tester Getting Started

This package is the current Cisco IOS-XE GUI test build. It runs the validated
L2 and NDM checks, displays results, optionally creates a text report, and fills
CKL output per successfully scanned switch.

## 1. Requirements

- Windows 10 or Windows 11
- Python 3.12
- Network connectivity to the Cisco IOS-XE switches
- An authorized SSH username and password

When installing Python, enable **Add Python to PATH**.

## 2. Extract and install

Extract the complete ZIP to a local folder. Do not run the application from
inside the ZIP.

Open PowerShell in the extracted `Stig_audit_pro` folder and run:

```powershell
python -m pip install -r requirements.txt
```

## 3. Start the GUI

```powershell
python app.py
```

## 4. Select or prepare a profile

Open the **Setup** tab, then **Profiles**. The supplied `base_iosxe_access`
profile contains the current test-site values.

Use **New** to create another site profile. Use letters, numbers, underscores,
or hyphens for the profile name. New profiles inherit `base_iosxe_access` by
default, so only add values that should override the base. Use **Delete** to
remove old site profiles; the base profile is protected.

A site-specific profile should inherit the base:

```yaml
profile_name: example_building
inherits: base_iosxe_access
```

Add only the values that differ for that site. Profiles can override native,
unused, and management VLANs; DHCP snooping and ARP inspection VLANs; upstream
Root Guard neighbors; and RADIUS group/server values.

The selected profile inherits the base file when `inherits: base_iosxe_access`
is set, and only the values present in the selected profile replace the base
values.

To review a new DISA release before editing these files, open **Setup** >
**Compare STIGs**, select the previous and current STIG ZIP/XML files, and run
the comparison. Select a difference to see the affected check YAML and any
base/site profile values. Use **Export Markdown** to save the change review.

## 5. Configure checklist output

Open the **Setup** tab, then **Checklist Output**:

1. Choose the reusable CKL templates, such as `templates\IOSXE_L2_Template.ckl`.
2. Select the destination folder.

## 6. Add targets and credentials

Open the **Audit Run** tab:

1. Add one IP, paste multiple IPs, or import a CSV/TXT list.
2. Check every target that should be audited.
3. Set **Scan Mode** to `Live SSH`.
4. Enter the SSH username and password.
5. Select a profile override for a target when it differs from the selected
   default profile.
6. Under **Run Options**, choose L2, NDM, or both.
7. Select **Fill CKL**, **Text report**, or both.
8. Choose whether generated comments append to or replace existing CKL comments.
9. Check the readiness list for anything that still needs attention.

Credentials are kept only for the running GUI session and are not written to
disk.

## 7. Run the checklist audit

Click **Run Checked Audit** on the **Audit Run** tab.

The CKL workflow requires `Live SSH` and will refuse to populate a checklist
from bundled sample output.

## 8. Review the output

The **Results** tab shows each check status and failed object details.

The selected destination receives:

- One `<hostname>_<IP>_<family>_completed.ckl` per selected CKL output.
- One combined `<family>_audit_<timestamp>.txt` when text reporting is selected.

The original CKL template is never overwritten.

The completed CKL receives the switch hostname and the IPv4 address configured
on the profile-defined management SVI (`management_vlan`, default VLAN 300).
If that address cannot be found, the scan target IP is used.

## 9. Expected temporary finding

`V-220651` is intentionally returned as `Open` until the site QoS policy is
implemented and that check is automated.

## Troubleshooting

- If results show `SW-ACCESS-01`, the Audit Run tab is using sample output instead
  of Live SSH.
- If DHCP snooping or ARP inspection VLANs fail, verify the selected target
  profile.
- If Root Guard fails, verify `root_guard.upstream_switches` contains the core
  or distribution CDP Device ID. Short hostnames match their FQDN form.
- Run the automated suite with:

```powershell
python -m pytest -q
```
