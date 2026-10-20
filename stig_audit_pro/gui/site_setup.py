"""GUI helpers for creating standalone site profiles and device groups."""

from __future__ import annotations

import csv
import ipaddress
import re
from pathlib import Path
from typing import Any, Callable, Mapping

from stig_audit_pro.storage.device_groups import (
    DeviceGroup,
    DeviceGroupStore,
    DeviceTargetRecord,
    normalize_device_addresses,
)
from stig_audit_pro.storage.profile_builder import (
    ProfileBuildError,
    load_profile_data,
    materialize_profile,
    safe_profile_filename,
    save_profile,
)


def _split_values(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[,;\n\t]+", value) if item.strip()]


def _int_list(value: str, label: str) -> list[int]:
    result: list[int] = []
    for item in _split_values(value):
        try:
            number = int(item)
        except ValueError as exc:
            raise ProfileBuildError(f"{label} must contain VLAN numbers") from exc
        if not 1 <= number <= 4094:
            raise ProfileBuildError(f"{label} VLAN {number} must be between 1 and 4094")
        if number not in result:
            result.append(number)
    return result


def _network_values(value: str) -> list[dict[str, str]]:
    networks: list[dict[str, str]] = []
    for item in _split_values(value):
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ProfileBuildError(f"Invalid management network: {item}") from exc
        networks.append(
            {
                "network_address": str(network.network_address),
                "subnet_mask": str(network.netmask),
            }
        )
    return networks


def _radius_addresses(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in _split_values(value):
        if "=" not in item:
            raise ProfileBuildError("RADIUS addresses must use SERVER=ADDRESS")
        name, address = (part.strip() for part in item.split("=", 1))
        if not name or not address:
            raise ProfileBuildError("RADIUS addresses must use SERVER=ADDRESS")
        try:
            ipaddress.ip_address(address)
        except ValueError as exc:
            raise ProfileBuildError(f"Invalid RADIUS server address: {address}") from exc
        result[name] = address
    return result


def _optional_positive_int(value: str, label: str) -> int | None:
    raw = value.strip()
    if not raw:
        return None
    try:
        result = int(raw)
    except ValueError as exc:
        raise ProfileBuildError(f"{label} must be a positive number") from exc
    if result < 1:
        raise ProfileBuildError(f"{label} must be a positive number")
    return result


def build_profile_overrides(values: Mapping[str, Any]) -> dict[str, Any]:
    """Convert friendly editor values into the existing profile YAML shape."""

    def required_int(key: str, label: str) -> int:
        raw = str(values.get(key, "")).strip()
        if not raw:
            raise ProfileBuildError(f"{label} is required")
        try:
            number = int(raw)
        except ValueError as exc:
            raise ProfileBuildError(f"{label} must be a VLAN number") from exc
        if not 1 <= number <= 4094:
            raise ProfileBuildError(f"{label} must be between 1 and 4094")
        return number

    variables: dict[str, Any] = {
        "site_label": str(values.get("site_label", "")).strip(),
        "required_user_vlans": _int_list(
            str(values.get("required_user_vlans", "")), "Required user"
        ),
    }
    for key, label in (
        ("logging_servers", "Logging servers"),
        ("ntp_servers", "NTP servers"),
        ("supported_iosxe_versions", "Supported IOS-XE versions"),
    ):
        raw = str(values.get(key, ""))
        if raw.strip():
            variables[key] = _split_values(raw)
    for key in ("local_password_policy", "tacacs_group"):
        raw = str(values.get(key, "")).strip()
        if raw:
            variables[key] = raw
    maximum = _optional_positive_int(
        str(values.get("max_concurrent_management_sessions", "")),
        "Maximum concurrent management sessions",
    )
    if maximum is not None:
        variables["max_concurrent_management_sessions"] = maximum

    return {
        "unused_vlan": required_int("unused_vlan", "Unused VLAN"),
        "native_vlan": required_int("native_vlan", "Native VLAN"),
        "management_vlan": required_int("management_vlan", "Management VLAN"),
        "dhcp_snooping": {
            "enabled": bool(values.get("dhcp_enabled", True)),
            "vlans": _int_list(str(values.get("dhcp_vlans", "")), "DHCP snooping"),
        },
        "arp_inspection": {
            "enabled": bool(values.get("arp_enabled", True)),
            "vlans": _int_list(str(values.get("arp_vlans", "")), "ARP inspection"),
        },
        "root_guard": {"upstream_switches": _split_values(str(values.get("root_guard_upstreams", "")))},
        "management_access": {
            "acl_name": str(values.get("management_acl", "")).strip(),
            "networks": _network_values(str(values.get("management_networks", ""))),
        },
        "endpoint_authentication": {
            "radius_group": str(values.get("radius_group", "")).strip(),
            "radius_servers": _split_values(str(values.get("radius_servers", ""))),
            "radius_server_addresses": _radius_addresses(str(values.get("radius_addresses", ""))),
        },
        "variables": variables,
    }


def parse_group_addresses(text: str) -> list[str]:
    """Parse a multiline/comma-separated group list with strict validation."""

    return normalize_device_addresses(re.split(r"[\r\n,;\t]+", text))


def _profile_form_values(data: Mapping[str, Any]) -> dict[str, Any]:
    dhcp = data.get("dhcp_snooping") or {}
    arp = data.get("arp_inspection") or {}
    root_guard = data.get("root_guard") or {}
    management = data.get("management_access") or {}
    endpoint = data.get("endpoint_authentication") or {}
    variables = data.get("variables") or {}
    networks = []
    for item in management.get("networks", []):
        if isinstance(item, Mapping):
            address = str(item.get("network_address", ""))
            mask = str(item.get("subnet_mask", ""))
            try:
                prefix = ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
                networks.append(f"{address}/{prefix}")
            except ValueError:
                networks.append(address)
    return {
        "unused_vlan": str(data.get("unused_vlan", 997)),
        "native_vlan": str(data.get("native_vlan", 20)),
        "management_vlan": str(data.get("management_vlan", 10)),
        "site_label": str(variables.get("site_label", data.get("profile_name", ""))),
        "required_user_vlans": ", ".join(map(str, variables.get("required_user_vlans", []))),
        "dhcp_vlans": ", ".join(map(str, dhcp.get("vlans", []))),
        "arp_vlans": ", ".join(map(str, arp.get("vlans", []))),
        "root_guard_upstreams": "\n".join(map(str, root_guard.get("upstream_switches", []))),
        "management_acl": str(management.get("acl_name", "")),
        "management_networks": "\n".join(networks),
        "radius_group": str(endpoint.get("radius_group", "")),
        "radius_servers": ", ".join(map(str, endpoint.get("radius_servers", []))),
        "radius_addresses": "\n".join(
            f"{name}={address}" for name, address in (endpoint.get("radius_server_addresses", {}) or {}).items()
        ),
        "logging_servers": ", ".join(map(str, variables.get("logging_servers", []))),
        "ntp_servers": ", ".join(map(str, variables.get("ntp_servers", []))),
        "supported_iosxe_versions": ", ".join(map(str, variables.get("supported_iosxe_versions", []))),
        "local_password_policy": str(variables.get("local_password_policy", "")),
        "tacacs_group": str(variables.get("tacacs_group", "")),
        "max_concurrent_management_sessions": str(variables.get("max_concurrent_management_sessions", "")),
        "dhcp_enabled": bool(dhcp.get("enabled", True)),
        "arp_enabled": bool(arp.get("enabled", True)),
    }


class SiteSetupPanel:
    """CustomTkinter panel for profile and device-group management."""

    def __init__(
        self,
        parent,
        *,
        profiles_dir: str | Path,
        groups_dir: str | Path,
        on_profiles_changed: Callable[[], None] | None = None,
        on_group_saved: Callable[[str], None] | None = None,
    ) -> None:
        import customtkinter as ctk
        from tkinter import filedialog, messagebox

        self.ctk = ctk
        self.filedialog = filedialog
        self.messagebox = messagebox
        self.profiles_dir = Path(profiles_dir)
        self.groups = DeviceGroupStore(groups_dir)
        self.on_profiles_changed = on_profiles_changed or (lambda: None)
        self.on_group_saved = on_group_saved or (lambda _name: None)
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        self.profile_fields: dict[str, Any] = {}
        self._build(parent)
        self._refresh_profile_choices()
        self._refresh_group_choices()
        self.new_profile()
        self.new_group()

    def _entry(self, parent, key: str, label: str, *, width: int = 240):
        row = self.ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=3)
        self.ctk.CTkLabel(row, text=label, width=180, anchor="w").pack(side="left")
        entry = self.ctk.CTkEntry(row, width=width)
        entry.pack(side="left", fill="x", expand=True)
        self.profile_fields[key] = entry
        return entry

    def _text(self, parent, key: str, label: str, *, height: int = 70):
        self.ctk.CTkLabel(parent, text=label, anchor="w").pack(fill="x", padx=8, pady=(7, 1))
        text = self.ctk.CTkTextbox(parent, height=height)
        text.pack(fill="x", padx=8, pady=(0, 3))
        self.profile_fields[key] = text
        return text

    def _build(self, parent) -> None:
        ctk = self.ctk
        tabs = ctk.CTkTabview(parent)
        tabs.pack(fill="both", expand=True, padx=8, pady=8)
        profiles = tabs.add("Site profiles")
        groups = tabs.add("Device groups")

        profile_scroll = ctk.CTkScrollableFrame(profiles)
        profile_scroll.pack(fill="both", expand=True)
        ctk.CTkLabel(profile_scroll, text="Create a self-contained building profile", anchor="w", font=ctk.CTkFont(size=18, weight="bold")).pack(fill="x", padx=8, pady=(8, 1))
        ctk.CTkLabel(profile_scroll, text="Choose a base once. Saved profiles contain the complete merged configuration.", anchor="w", wraplength=800).pack(fill="x", padx=8, pady=(0, 8))
        top = ctk.CTkFrame(profile_scroll, fg_color="transparent")
        top.pack(fill="x", padx=8, pady=3)
        self.profile_choice = ctk.CTkOptionMenu(top, values=["New profile"], command=self._select_profile)
        self.profile_choice.pack(side="left", padx=(0, 6))
        self.base_choice = ctk.CTkOptionMenu(top, values=["base_iosxe_access"], command=self._select_base)
        self.base_choice.pack(side="left", padx=6)
        ctk.CTkButton(top, text="New profile", command=self.new_profile).pack(side="left", padx=6)
        ctk.CTkButton(top, text="Delete", command=self.delete_profile).pack(side="left", padx=6)
        self.profile_name = ctk.CTkEntry(profile_scroll, placeholder_text="Saved profile name, e.g. Building 1")
        self.profile_name.pack(fill="x", padx=8, pady=4)
        self._entry(profile_scroll, "site_label", "Site label")
        self._entry(profile_scroll, "unused_vlan", "Unused VLAN")
        self._entry(profile_scroll, "native_vlan", "Native VLAN")
        self._entry(profile_scroll, "management_vlan", "Management VLAN")
        self._entry(profile_scroll, "management_acl", "Management ACL")
        self._entry(profile_scroll, "radius_group", "RADIUS group")
        self._entry(profile_scroll, "radius_servers", "RADIUS servers")
        self._entry(profile_scroll, "logging_servers", "Logging servers")
        self._entry(profile_scroll, "ntp_servers", "NTP servers")
        self._entry(profile_scroll, "supported_iosxe_versions", "Supported IOS-XE versions")
        self._entry(profile_scroll, "local_password_policy", "Local password policy")
        self._entry(profile_scroll, "tacacs_group", "TACACS group")
        self._entry(profile_scroll, "max_concurrent_management_sessions", "Max management sessions")
        self._text(profile_scroll, "required_user_vlans", "Required user VLANs (comma-separated)", height=48)
        self._text(profile_scroll, "dhcp_vlans", "DHCP snooping VLANs (comma-separated)", height=48)
        self._text(profile_scroll, "arp_vlans", "ARP inspection VLANs (comma-separated)", height=48)
        self._text(profile_scroll, "root_guard_upstreams", "Root Guard upstream switches (one per line)", height=60)
        self._text(profile_scroll, "management_networks", "Approved management networks (CIDR, one per line)", height=60)
        self._text(profile_scroll, "radius_addresses", "RADIUS addresses (SERVER=IP, one per line)", height=60)
        switches = ctk.CTkFrame(profile_scroll, fg_color="transparent")
        switches.pack(fill="x", padx=8, pady=3)
        self.dhcp_enabled = ctk.BooleanVar(value=True)
        self.arp_enabled = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(switches, text="DHCP snooping enabled", variable=self.dhcp_enabled).pack(side="left", padx=6)
        ctk.CTkCheckBox(switches, text="ARP inspection enabled", variable=self.arp_enabled).pack(side="left", padx=6)
        ctk.CTkButton(profile_scroll, text="Save standalone site profile", command=self.save_current_profile).pack(anchor="w", padx=8, pady=8)

        group_scroll = ctk.CTkScrollableFrame(groups)
        group_scroll.pack(fill="both", expand=True)
        ctk.CTkLabel(group_scroll, text="Create a reusable building device group", anchor="w", font=ctk.CTkFont(size=18, weight="bold")).pack(fill="x", padx=8, pady=(8, 1))
        ctk.CTkLabel(group_scroll, text="Select the group on the Audit tab to load its devices and profile.", anchor="w").pack(fill="x", padx=8, pady=(0, 8))
        group_top = ctk.CTkFrame(group_scroll, fg_color="transparent")
        group_top.pack(fill="x", padx=8, pady=3)
        self.group_choice = ctk.CTkOptionMenu(group_top, values=["New group"], command=self._select_group)
        self.group_choice.pack(side="left", padx=(0, 6))
        ctk.CTkButton(group_top, text="New group", command=self.new_group).pack(side="left", padx=6)
        ctk.CTkButton(group_top, text="Delete", command=self.delete_group).pack(side="left", padx=6)
        self.group_name = ctk.CTkEntry(group_scroll, placeholder_text="Group name, e.g. Building 1")
        self.group_name.pack(fill="x", padx=8, pady=4)
        profile_row = ctk.CTkFrame(group_scroll, fg_color="transparent")
        profile_row.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(profile_row, text="Profile", width=180, anchor="w").pack(side="left")
        self.group_profile = ctk.CTkOptionMenu(profile_row, values=["base_iosxe_access"])
        self.group_profile.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(group_scroll, text="Device addresses (IP or hostname, one per line)", anchor="w").pack(fill="x", padx=8, pady=(7, 1))
        self.group_devices = ctk.CTkTextbox(group_scroll, height=230)
        self.group_devices.pack(fill="both", expand=True, padx=8, pady=(0, 3))
        group_actions = ctk.CTkFrame(group_scroll, fg_color="transparent")
        group_actions.pack(fill="x", padx=8, pady=8)
        ctk.CTkButton(group_actions, text="Import CSV/TXT", command=self.import_group_devices).pack(side="left", padx=4)
        ctk.CTkButton(group_actions, text="Save device group", command=self.save_current_group).pack(side="left", padx=4)

    def _names(self) -> list[str]:
        return sorted(path.stem for path in self.profiles_dir.glob("*.yaml"))

    def _refresh_profile_choices(self) -> None:
        names = self._names()
        values = ["New profile"] + names
        self.profile_choice.configure(values=values)
        self.group_profile.configure(values=names or ["base_iosxe_access"])
        if names and self.group_profile.get() not in names:
            self.group_profile.set(names[0])
        self.base_choice.configure(values=names or ["base_iosxe_access"])

    def _refresh_group_choices(self) -> None:
        names = self.groups.list_groups()
        self.group_choice.configure(values=["New group"] + names)

    def _clear(self, widget) -> None:
        if hasattr(widget, "delete"):
            widget.delete("1.0", "end") if isinstance(widget, self.ctk.CTkTextbox) else widget.delete(0, "end")

    def _set(self, key: str, value: Any) -> None:
        widget = self.profile_fields[key]
        self._clear(widget)
        text = str(value)
        if isinstance(widget, self.ctk.CTkTextbox):
            widget.insert("1.0", text)
        else:
            widget.insert(0, text)

    def _get(self, key: str) -> str:
        widget = self.profile_fields[key]
        return widget.get("1.0", "end").strip() if isinstance(widget, self.ctk.CTkTextbox) else widget.get().strip()

    def _load_form(self, data: Mapping[str, Any]) -> None:
        values = _profile_form_values(data)
        for key, value in values.items():
            if key not in {"dhcp_enabled", "arp_enabled"}:
                self._set(key, value)
        self.dhcp_enabled.set(values["dhcp_enabled"])
        self.arp_enabled.set(values["arp_enabled"])

    def new_profile(self) -> None:
        self.profile_choice.set("New profile")
        self.profile_name.delete(0, "end")
        bases = self._names()
        base = "base_iosxe_access" if "base_iosxe_access" in bases else (bases[0] if bases else "base_iosxe_access")
        self.base_choice.set(base)
        self._select_base(base)

    def _select_base(self, name: str) -> None:
        try:
            data = load_profile_data(self.profiles_dir / safe_profile_filename(name))
        except ProfileBuildError:
            data = {"profile_name": name}
        self._load_form(data)

    def _select_profile(self, name: str) -> None:
        if name == "New profile":
            self.new_profile()
            return
        try:
            data = load_profile_data(self.profiles_dir / safe_profile_filename(name))
            self.profile_name.delete(0, "end")
            self.profile_name.insert(0, str(data.get("profile_name", name)))
            self.base_choice.set(name)
            self._load_form(data)
        except ProfileBuildError as exc:
            self.messagebox.showerror("Profile could not be loaded", str(exc))

    def save_current_profile(self) -> None:
        try:
            name = self.profile_name.get().strip()
            if not name or name.startswith("base_"):
                raise ProfileBuildError("Choose a new site profile name that does not start with base_")
            base = load_profile_data(self.profiles_dir / safe_profile_filename(self.base_choice.get()))
            fields = {key: self._get(key) for key in self.profile_fields}
            fields.update({"dhcp_enabled": self.dhcp_enabled.get(), "arp_enabled": self.arp_enabled.get()})
            data = materialize_profile(base, build_profile_overrides(fields), name)
            file_stem = Path(safe_profile_filename(name)).stem
            destination = self.profiles_dir / f"{file_stem}.yaml"
            if destination.exists() and not self.messagebox.askyesno("Replace profile?", f"Replace the saved profile {name}?"):
                return
            save_profile(destination, data, self.profiles_dir)
            self._refresh_profile_choices()
            self.profile_choice.set(file_stem)
            self.messagebox.showinfo("Profile saved", f"Standalone profile saved:\n{destination}")
            self.on_profiles_changed()
        except (OSError, ProfileBuildError) as exc:
            self.messagebox.showerror("Profile not saved", str(exc))

    def delete_profile(self) -> None:
        name = self.profile_choice.get()
        if name == "New profile" or name.startswith("base_"):
            self.messagebox.showinfo("Base profile", "Base profiles are templates and cannot be deleted here.")
            return
        if not self.messagebox.askyesno("Delete profile?", f"Delete the saved profile {name}?"):
            return
        try:
            (self.profiles_dir / safe_profile_filename(name)).unlink()
            self._refresh_profile_choices()
            self.new_profile()
            self.on_profiles_changed()
        except OSError as exc:
            self.messagebox.showerror("Profile not deleted", str(exc))

    def new_group(self) -> None:
        self.group_choice.set("New group")
        self.group_name.delete(0, "end")
        self.group_devices.delete("1.0", "end")
        values = self._names()
        self.group_profile.set(values[0] if values else "base_iosxe_access")

    def _select_group(self, name: str) -> None:
        if name == "New group":
            self.new_group()
            return
        try:
            group = self.groups.load_group(name)
            self.group_name.delete(0, "end")
            self.group_name.insert(0, group.group_name)
            self.group_profile.set(group.profile_name or "base_iosxe_access")
            self.group_devices.delete("1.0", "end")
            self.group_devices.insert("1.0", "\n".join(target.ip for target in group.targets))
        except (OSError, ValueError) as exc:
            self.messagebox.showerror("Group could not be loaded", str(exc))

    def save_current_group(self) -> None:
        try:
            name = self.group_name.get().strip()
            if not name:
                raise ValueError("Group name is required")
            addresses = parse_group_addresses(self.group_devices.get("1.0", "end"))
            profile = self.group_profile.get().strip()
            if not profile:
                raise ValueError("Choose a profile for this group")
            destination = self.groups.path_for(name)
            if destination.exists() and not self.messagebox.askyesno("Replace group?", f"Replace the saved group {name}?"):
                return
            self.groups.save_group(
                DeviceGroup(
                    group_name=name,
                    profile_name=profile,
                    targets=[DeviceTargetRecord(ip=address) for address in addresses],
                )
            )
            self._refresh_group_choices()
            self.group_choice.set(name)
            self.messagebox.showinfo("Device group saved", f"Saved {len(addresses)} device(s) in {name}.")
            self.on_group_saved(name)
        except (OSError, ValueError) as exc:
            self.messagebox.showerror("Group not saved", str(exc))

    def delete_group(self) -> None:
        name = self.group_choice.get()
        if name == "New group":
            return
        if not self.messagebox.askyesno("Delete group?", f"Delete the saved group {name}?"):
            return
        try:
            self.groups.path_for(name).unlink()
            self._refresh_group_choices()
            self.new_group()
        except OSError as exc:
            self.messagebox.showerror("Group not deleted", str(exc))

    def import_group_devices(self) -> None:
        selected = self.filedialog.askopenfilename(filetypes=[("Device list", "*.csv *.txt"), ("All files", "*.*")])
        if not selected:
            return
        try:
            path = Path(selected)
            if path.suffix.casefold() == ".csv":
                with path.open(encoding="utf-8-sig", newline="") as handle:
                    rows = list(csv.reader(handle))
                if not rows:
                    raise ValueError("The file is empty")
                headers = [item.strip().casefold() for item in rows[0]]
                header = next((item for item in ("ip", "address", "host", "hostname") if item in headers), None)
                index = headers.index(header) if header else 0
                rows = rows[1:] if header else rows
                text = "\n".join(row[index] for row in rows if len(row) > index)
            else:
                text = path.read_text(encoding="utf-8-sig")
            addresses = parse_group_addresses(text)
            self.group_devices.delete("1.0", "end")
            self.group_devices.insert("1.0", "\n".join(addresses))
            self.messagebox.showinfo("Device list imported", f"Loaded {len(addresses)} device(s).")
        except (OSError, ValueError) as exc:
            self.messagebox.showerror("Import failed", str(exc))


__all__ = ["SiteSetupPanel", "build_profile_overrides", "parse_group_addresses"]
