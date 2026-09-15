"""Guided Devices → STIG → Site Profile → Readiness audit workflow."""

from __future__ import annotations

import customtkinter as ctk

from stig_audit_pro.application.preflight_service import PreflightSeverity


class AuditWizard(ctk.CTkToplevel):
    STEPS = ("1  Devices", "2  STIG", "3  Site Profile", "4  Readiness")

    def __init__(self, master, app_controller) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.step = 0
        self.title("Start an Assessment")
        self.geometry("760x590")
        self.minsize(680, 520)
        self.transient(master)
        self.grab_set()
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self.step_label = ctk.CTkSegmentedButton(self, values=list(self.STEPS), state="disabled")
        self.step_label.set(self.STEPS[0])
        self.step_label.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))
        self.content = ctk.CTkFrame(self)
        self.content.grid(row=1, column=0, sticky="nsew", padx=18, pady=8)
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(1, weight=1)
        controls = ctk.CTkFrame(self, fg_color="transparent")
        controls.grid(row=2, column=0, sticky="ew", padx=18, pady=(8, 18))
        controls.grid_columnconfigure(1, weight=1)
        self.back = ctk.CTkButton(controls, text="Back", width=100, command=self._back)
        self.back.grid(row=0, column=0)
        self.cancel = ctk.CTkButton(controls, text="Cancel", width=100, fg_color="transparent", border_width=1, command=self.destroy)
        self.cancel.grid(row=0, column=2, padx=8)
        self.next = ctk.CTkButton(controls, text="Next", width=130, command=self._next)
        self.next.grid(row=0, column=3)
        self._render()

    def _render(self) -> None:
        for child in self.content.winfo_children():
            child.destroy()
        self.step_label.set(self.STEPS[self.step])
        self.back.configure(state="normal" if self.step else "disabled")
        self.next.configure(text="Start Audit" if self.step == 3 else "Next")
        title, body = self._step_content()
        ctk.CTkLabel(self.content, text=title, font=ctk.CTkFont(size=22, weight="bold"), anchor="w").grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))
        text = ctk.CTkTextbox(self.content, wrap="word", font=ctk.CTkFont(size=14))
        text.grid(row=1, column=0, sticky="nsew", padx=18, pady=(4, 18))
        text.insert("1.0", body)
        text.configure(state="disabled")

    def _step_content(self) -> tuple[str, str]:
        targets = self.app_controller.targets_tab.get_targets("checked")
        families = self.app_controller.targets_tab.get_audit_run_settings()["families"]
        checks = [check for check in self.app_controller.checks if check.stig_family in families]
        if self.step == 0:
            return "Choose devices", (
                f"{len(targets)} device(s) are currently selected.\n\n"
                "Use the Audit Run workspace to add individual switches, import a CSV, load a saved group, or change the selection.\n\n"
                "Select Next when the device list is ready. This step does not contact any device."
            )
        if self.step == 1:
            labels = ", ".join(family.replace("IOSXE_", "Cisco IOS-XE ") for family in sorted(families)) or "None selected"
            automated = sum(1 for check in checks if check.automated and check.check_type != "manual_review")
            manual = len(checks) - automated
            return "Choose the STIG", f"Selected: {labels}\n\nAutomated checks: {automated}\nManual checks: {manual}\n\nSTIG release maintenance and automation readiness are available in the STIG Update Center."
        if self.step == 2:
            profile = self.app_controller.profile
            if profile is None:
                details = "No Site Profile is loaded."
            else:
                details = (
                    f"{profile.profile_name}\n\nManagement VLAN: {profile.management_vlan}\n"
                    f"Unused VLAN: {profile.unused_vlan}\nNative VLAN: {profile.native_vlan}\n"
                    f"RADIUS servers: {', '.join(profile.endpoint_authentication.radius_servers) or 'Not set'}"
                )
            return "Review the Site Profile", details + "\n\nUse Profiles to review or change site-specific settings before the audit."
        result = self.app_controller.build_preflight_result()
        lines = ["Ready to audit" if result.ready else "Action required before audit", ""]
        icons = {PreflightSeverity.INFO: "✓", PreflightSeverity.WARNING: "⚠", PreflightSeverity.BLOCKING: "✕"}
        for issue in result.issues:
            lines.append(f"{icons[issue.severity]} {issue.message}")
            if issue.guidance:
                lines.append(f"   {issue.guidance}")
        lines.extend(("", "✓ Commands are limited by the read-only command policy."))
        return "Pre-audit readiness", "\n".join(lines)

    def _next(self) -> None:
        if self.step < 3:
            self.step += 1
            self._render()
            return
        result = self.app_controller.build_preflight_result()
        if not result.ready:
            self._render()
            return
        self.destroy()
        self.app_controller.run_configured_checklist_audit()

    def _back(self) -> None:
        if self.step:
            self.step -= 1
            self._render()


__all__ = ["AuditWizard"]
