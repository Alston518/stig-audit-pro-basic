"""Typed site-profile editor with an advanced YAML escape hatch."""

from __future__ import annotations

from pathlib import Path

import customtkinter as ctk

from stig_audit_pro.config import DEFAULT_PROFILE_NAME
from stig_audit_pro.core.models import SiteProfile
from stig_audit_pro.gui.widgets import PageFrame, Panel, confirm_action, label_value
from stig_audit_pro.gui.yaml_editor import YamlEditor


class ProfilesTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.current_yaml_path: Path | None = None
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(0, weight=1)

        left = Panel(self, "Effective Profile")
        left.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=12)
        left.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(left, text="Site Profile").grid(row=1, column=0, sticky="w", padx=12, pady=(8, 4))
        self.profile_select = ctk.CTkComboBox(
            left, values=[DEFAULT_PROFILE_NAME], command=self._profile_selected,
            state="readonly",
        )
        self.profile_select.set(DEFAULT_PROFILE_NAME)
        self.profile_select.grid(row=1, column=1, sticky="ew", padx=12, pady=(8, 4))
        profile_actions = ctk.CTkFrame(left, fg_color="transparent")
        profile_actions.grid(
            row=2, column=0, columnspan=2, sticky="ew", padx=12, pady=(4, 8)
        )
        profile_actions.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(
            profile_actions,
            text="New Profile",
            command=self._new_profile,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ctk.CTkButton(
            profile_actions,
            text="Delete Profile",
            command=self._delete_profile,
            fg_color="#b42318",
            hover_color="#912018",
        ).grid(row=0, column=1, sticky="ew", padx=(4, 0))
        self.value_labels: dict[str, ctk.CTkLabel] = {}
        labels = [
            ("profile_name", "Name"), ("unused_vlan", "Unused VLAN"),
            ("native_vlan", "Native VLAN"), ("management_vlan", "Management VLAN"),
            ("disabled_vlan", "Disabled Port VLAN"), ("trunk_prune", "VLAN 1 Pruned"),
            ("dhcp_vlans", "DHCP Snooping VLANs"), ("arp_vlans", "ARP Inspection VLANs"),
        ]
        for offset, (key, text) in enumerate(labels, start=3):
            self.value_labels[key] = label_value(left, offset, text, "-")
        ctk.CTkButton(left, text="Reload Profile", command=app_controller.reload_from_disk).grid(
            row=12, column=0, columnspan=2, sticky="ew", padx=12, pady=(18, 6)
        )
        self.consumer_note = ctk.CTkLabel(
            left,
            text=(
                "Profile values are consumed by VLAN, trunk, DHCP snooping, ARP inspection, "
                "management-access, RADIUS, and root-guard policy checks."
            ),
            anchor="w", justify="left", wraplength=320,
            text_color=("#475467", "#d0d5dd"),
        )
        self.consumer_note.grid(row=13, column=0, columnspan=2, sticky="ew", padx=12, pady=(6, 12))

        editor_tabs = ctk.CTkTabview(self)
        editor_tabs.grid(row=0, column=1, sticky="nsew", padx=(6, 12), pady=12)
        simple_page = editor_tabs.add("Simple Editor")
        yaml_page = editor_tabs.add("Advanced YAML")
        for page in (simple_page, yaml_page):
            page.grid_columnconfigure(0, weight=1)
            page.grid_rowconfigure(0, weight=1)

        form = ctk.CTkScrollableFrame(simple_page)
        form.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
        form.grid_columnconfigure(1, weight=1)
        self.fields: dict[str, ctk.CTkEntry] = {}
        field_specs = [
            ("unused_vlan", "Unused VLAN", "999"),
            ("native_vlan", "Native VLAN", "333"),
            ("management_vlan", "Management VLAN", "300"),
            ("dhcp_vlans", "DHCP snooping VLANs", "10, 20, 30"),
            ("arp_vlans", "ARP inspection VLANs", "10, 20, 30"),
            ("additional_pruned_vlans", "Additional pruned VLANs", "100, 200"),
            ("management_networks", "Management networks", "10.0.0.0 255.255.255.0"),
            ("radius_servers", "RADIUS server names", "ISE01, ISE02"),
            ("root_guard_upstream", "Root guard/upstream switches", "DIST01, DIST02"),
        ]
        for row, (key, label, placeholder) in enumerate(field_specs):
            ctk.CTkLabel(form, text=label, anchor="w").grid(
                row=row, column=0, sticky="w", padx=(10, 8), pady=6
            )
            entry = ctk.CTkEntry(form, placeholder_text=placeholder)
            entry.grid(row=row, column=1, sticky="ew", padx=(8, 10), pady=6)
            self.fields[key] = entry
        self.variables = ctk.CTkTextbox(form, height=150, wrap="none")
        ctk.CTkLabel(form, text="Additional profile variables (YAML mapping)", anchor="w").grid(
            row=len(field_specs), column=0, sticky="nw", padx=(10, 8), pady=6
        )
        self.variables.grid(row=len(field_specs), column=1, sticky="ew", padx=(8, 10), pady=6)
        simple_actions = ctk.CTkFrame(form, fg_color="transparent")
        simple_actions.grid(row=len(field_specs) + 1, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        simple_actions.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(simple_actions, text="Validate Values", command=self._validate_simple).grid(
            row=0, column=0, sticky="ew", padx=(0, 6)
        )
        ctk.CTkButton(simple_actions, text="Save Profile Values", command=self._save_simple).grid(
            row=0, column=1, sticky="ew", padx=(6, 0)
        )
        self.simple_status = ctk.CTkLabel(form, text="", anchor="w")
        self.simple_status.grid(row=len(field_specs) + 2, column=0, columnspan=2, sticky="ew", padx=10)

        yaml_page.grid_rowconfigure(0, weight=1)
        self.editor = YamlEditor(yaml_page, "Profile YAML")
        self.editor.grid(row=0, column=0, sticky="nsew")
        yaml_actions = ctk.CTkFrame(yaml_page, fg_color="transparent")
        yaml_actions.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        yaml_actions.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(yaml_actions, text="Validate YAML", command=self._validate_yaml).grid(
            row=0, column=0, sticky="ew", padx=(0, 6)
        )
        ctk.CTkButton(yaml_actions, text="Save YAML", command=self._save_yaml).grid(
            row=0, column=1, sticky="ew", padx=(6, 0)
        )

    def refresh(self, profile: SiteProfile, yaml_path: Path) -> None:
        import yaml

        self.current_yaml_path = yaml_path
        values = self.app_controller.available_profile_names()
        self.profile_select.configure(values=values)
        self.profile_select.set(profile.profile_name)
        self.editor.set_text(yaml_path.read_text(encoding="utf-8"))
        self.editor.set_status("Profile loaded")
        self.value_labels["profile_name"].configure(text=profile.profile_name)
        self.value_labels["unused_vlan"].configure(text=str(profile.unused_vlan))
        self.value_labels["native_vlan"].configure(text=str(profile.native_vlan))
        self.value_labels["management_vlan"].configure(text=str(profile.management_vlan))
        self.value_labels["disabled_vlan"].configure(text=str(profile.disabled_port_policy.required_access_vlan))
        self.value_labels["trunk_prune"].configure(text=str(profile.trunk_policy.vlan_1_must_be_pruned))
        self.value_labels["dhcp_vlans"].configure(text=", ".join(map(str, profile.dhcp_snooping.vlans)))
        self.value_labels["arp_vlans"].configure(text=", ".join(map(str, profile.arp_inspection.vlans)))
        editable = {
            "unused_vlan": str(profile.unused_vlan),
            "native_vlan": str(profile.native_vlan),
            "management_vlan": str(profile.management_vlan),
            "dhcp_vlans": ", ".join(map(str, profile.dhcp_snooping.vlans)),
            "arp_vlans": ", ".join(map(str, profile.arp_inspection.vlans)),
            "additional_pruned_vlans": ", ".join(map(str, profile.trunk_policy.additional_pruned_vlans)),
            "management_networks": "; ".join(
                f"{item.network_address} {item.subnet_mask}" for item in profile.management_access.networks
            ),
            "radius_servers": ", ".join(profile.endpoint_authentication.radius_servers),
            "root_guard_upstream": ", ".join(profile.root_guard.upstream_switches),
        }
        for key, text in editable.items():
            self.fields[key].delete(0, "end")
            self.fields[key].insert(0, text)
        self.variables.delete("1.0", "end")
        self.variables.insert("1.0", yaml.safe_dump(profile.variables, sort_keys=False).strip())

    def _profile_selected(self, value: str) -> None:
        self.app_controller.select_profile(value)

    def _new_profile(self) -> None:
        dialog = ctk.CTkInputDialog(
            title="New Site Profile",
            text="Profile name (letters, numbers, underscores, or hyphens):",
        )
        profile_name = (dialog.get_input() or "").strip()
        if not profile_name:
            self.simple_status.configure(text="Profile creation cancelled")
            return
        ok, message = self.app_controller.create_profile(profile_name)
        self.simple_status.configure(
            text=message,
            text_color=("#027a48", "#6ce9a6") if ok else ("#b42318", "#f97066"),
        )

    def _delete_profile(self) -> None:
        profile_name = self.profile_select.get().strip()
        if not profile_name:
            self.simple_status.configure(text="Choose a profile to delete")
            return
        if profile_name == DEFAULT_PROFILE_NAME:
            self.simple_status.configure(text="The base profile cannot be deleted")
            return
        if not confirm_action(
            self,
            title="Delete Site Profile?",
            message=(
                f"Delete the profile '{profile_name}'?\n\n"
                "Device groups that reference it will need a new Site Profile. "
                "This cannot be undone."
            ),
            confirm_text="Delete Profile",
        ):
            self.simple_status.configure(text="Profile deletion cancelled")
            return
        ok, message = self.app_controller.delete_profile(profile_name)
        self.simple_status.configure(
            text=message,
            text_color=("#027a48", "#6ce9a6") if ok else ("#b42318", "#f97066"),
        )

    def _simple_values(self) -> dict[str, str]:
        return {key: entry.get() for key, entry in self.fields.items()} | {
            "variables_yaml": self.variables.get("1.0", "end").strip()
        }

    def _validate_simple(self) -> None:
        ok, message = self.app_controller.validate_profile_values(self._simple_values())
        self.simple_status.configure(text=message, text_color=("#027a48", "#6ce9a6") if ok else ("#b42318", "#f97066"))

    def _save_simple(self) -> None:
        if self.current_yaml_path is None:
            self.simple_status.configure(text="Choose a profile first")
            return
        ok, message = self.app_controller.save_profile_values(self.current_yaml_path, self._simple_values())
        self.simple_status.configure(text=message, text_color=("#027a48", "#6ce9a6") if ok else ("#b42318", "#f97066"))

    def _validate_yaml(self) -> None:
        ok, message = self.app_controller.validate_profile_yaml(self.editor.get_text())
        self.editor.set_status(message, ok=ok)

    def _save_yaml(self) -> None:
        if self.current_yaml_path is None:
            self.editor.set_status("Choose a profile first", ok=False)
            return
        ok, message = self.app_controller.save_profile_yaml(self.current_yaml_path, self.editor.get_text())
        self.editor.set_status(message, ok=ok)


__all__ = ["ProfilesTab"]
