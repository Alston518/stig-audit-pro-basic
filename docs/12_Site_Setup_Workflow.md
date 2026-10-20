# Site setup workflow

The Basic app can create site profiles and reusable device groups without editing YAML by hand.

## Create a site profile

1. Open **Profiles & Sites → Site profiles**.
2. Select **New profile**.
3. Choose a base profile. This is only needed while creating the site profile.
4. Enter the values that apply to the building: VLANs, management networks, Root Guard upstreams, RADIUS details, and site label.
5. Select **Save standalone site profile**.

The app validates the complete configuration and saves one flattened YAML file in the application's `data/profiles` directory. The saved file does not depend on the base profile. If the base template changes later, the existing building profile remains the same until the operator edits it.

### Override rules

- Nested sections merge into the base profile.
- Text and numeric values entered in the editor replace the base value.
- Lists replace the entire base list. For example, entering `110, 120, 130` for DHCP snooping VLANs replaces the base DHCP list.
- Clearing a list is intentional and saves an empty list.

## Create a device group

1. Open **Profiles & Sites → Device groups**.
2. Enter a name such as `Building 1`.
3. Select the saved site profile.
4. Paste one IP address or hostname per line, or use **Import CSV/TXT**.
5. Select **Save device group**.

The app rejects malformed and duplicate addresses and requires at least one device. Group files are saved in `data/device_groups`.

## Run a saved building

1. Open the **Audit** tab.
2. Choose the building in **Saved building**.
3. Review the device count, selected profile, platform, STIG family, and output folder.
4. Enter SSH credentials only for a live SSH run. They remain in memory and are cleared after the run starts.
5. Select **Start audit**.

Selecting a saved building fills the device list and profile for the run. Manual device entry remains available by choosing **Manual device list**.

## Storage and security

Profiles and device groups contain network configuration and inventory. They never contain SSH passwords or enable secrets. Protect the application's data directory with the host's approved access controls and backups. Audit reports continue to be written as encrypted `.sapenc` files by the at-rest encryption workflow.
