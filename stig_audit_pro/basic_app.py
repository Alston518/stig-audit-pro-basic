"""Operator-first, read-only STIG audit workflow for the Basic edition."""
from __future__ import annotations
import csv, hashlib, ipaddress, json, logging, os, queue, re, threading, uuid, shutil, sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from stig_audit_pro.application.audit_service import AuditService
from stig_audit_pro.build_info import load_build_metadata
from stig_audit_pro.core.ssh_runner import DeviceCredentials
from stig_audit_pro.core.yaml_loader import ConfigValidationError, load_check_library, load_profile
from stig_audit_pro.reports.audit_report import build_text_report
from stig_audit_pro.reports.basic_summary import Filter, STATUSES, CATS, cat, summarize, render_csv, render_html, render_pdf
from stig_audit_pro.stig.ckl_writer import render_completed_ckl
from stig_audit_pro.storage.device_groups import DeviceGroup, DeviceGroupStore, DeviceTargetRecord
from stig_audit_pro.storage.profile_builder import ProfileBuildError, load_profile_data
from stig_audit_pro.licensing import LicenseImportError, LicensePolicyError
from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy, normalize_basic_targets
from stig_audit_pro.infrastructure.security.at_rest import AtRestVault, VaultUnlockError
from stig_audit_pro.infrastructure.security.basic_artifacts import ProtectedArtifactStore, default_vault_path

COMMAND_FILES = {
    "show running-config":"show_running_config.txt", "show vtp status":"show_vtp_status.txt",
    "show interfaces status":"show_interfaces_status.txt",
    "show interfaces switchport | include Negotiation of Trunking":"show_interfaces_switchport_negotiation.txt",
    "show interfaces trunk":"show_interfaces_trunk.txt", "show cdp neighbors detail":"show_cdp_neighbors_detail.txt",
    "show ip access-lists":"show_ip_access_lists.txt", "show ip dhcp snooping":"show_ip_dhcp_snooping.txt",
    "show ip arp inspection":"show_ip_arp_inspection.txt", "show snmp user":"show_snmp_user.txt",
    "show running-config | include ssh":"show_running_config_include_ssh.txt", "show version":"show_version.txt",
}

PLATFORM_PREFIXES = {"IOS XE": "iosxe", "IOS": "ios"}
FAMILY_CHOICES = {"L2": ("l2",), "NDM": ("ndm",), "L2 + NDM": ("l2", "ndm")}
DEFAULT_PROFILES = {"IOS XE": "base_iosxe_access", "IOS": "base_ios_switch_access"}
TEMPLATE_FILENAMES = {
    "IOS XE": {"L2": "IOSXE_L2_Template.ckl", "NDM": "IOSXE_NDM_Template.ckl", "L2 + NDM": "IOSXE_L2_NDM_Template.ckl"},
    "IOS": {"L2": "IOS_L2_Template.ckl", "NDM": "IOS_NDM_Template.ckl", "L2 + NDM": "IOS_L2_NDM_Template.ckl"},
}


def library_names(platform: str, family_choice: str) -> list[str]:
    """Return the check libraries selected in the Basic audit screen."""
    try:
        prefix = PLATFORM_PREFIXES[platform]
        families = FAMILY_CHOICES[family_choice]
    except KeyError as exc:
        raise ValueError(f"Unsupported audit selection: {platform}, {family_choice}") from exc
    return [f"{prefix}_{family}" for family in families]


def default_profile_name(platform: str) -> str:
    return DEFAULT_PROFILES[platform]


def selected_group_values(group: DeviceGroup) -> tuple[list[str], str | None]:
    """Return checked addresses and the saved profile for an audit group."""

    return [target.ip for target in group.targets if target.checked], group.profile_name


def can_use_sample_outputs(platform: str) -> bool:
    """The bundled sample output was captured from IOS XE devices only."""
    return platform == "IOS XE"


def template_paths(platform: str, families: list[str], paths_by_platform: dict[str, dict[str, str]]) -> dict[str, str]:
    """Use only CKL templates assigned to the selected switch platform."""
    selected = paths_by_platform[platform]
    templates = {"combined": selected["L2 + NDM"]}
    for family in families:
        templates[family] = selected["L2"] if family.endswith("_l2") else selected["NDM"]
    return templates


def template_slot_path(folder: Path, platform: str, choice: str) -> Path:
    return folder / TEMPLATE_FILENAMES[platform][choice]


def existing_template_selections(folder: Path) -> dict[str, dict[str, str]]:
    return {
        platform: {
            choice: str(path) if path.is_file() else ""
            for choice in choices
            for path in (template_slot_path(folder, platform, choice),)
        }
        for platform, choices in TEMPLATE_FILENAMES.items()
    }


def save_template_selection(source: str | Path, slot: Path) -> Path:
    source = Path(source).expanduser().resolve()
    slot = slot.resolve()
    if not source.is_file() or source.suffix.casefold() not in {".ckl", ".xml"}:
        raise ValueError(f"Choose an existing CKL or XML template: {source}")
    if source == slot:
        return slot
    slot.parent.mkdir(parents=True, exist_ok=True)
    temporary = slot.with_name(slot.name + ".tmp")
    try:
        shutil.copy2(source, temporary)
        temporary.replace(slot)
    finally:
        temporary.unlink(missing_ok=True)
    return slot


def load_template_paths(folder: Path, old_folder: Path, settings: Path) -> dict[str, dict[str, str]]:
    try: saved=json.loads(settings.read_text(encoding='utf-8'))
    except (OSError,ValueError): saved={}
    if not isinstance(saved,dict):saved={}
    found={}
    for platform,choices in TEMPLATE_FILENAMES.items():
        found[platform]={}
        values=saved.get(platform,{})
        if not isinstance(values,dict):values={}
        for choice,name in choices.items():
            raw=values.get(choice,'')
            selected=folder/Path(raw[8:]).name if isinstance(raw,str) and raw.startswith('project:') else Path(raw) if isinstance(raw,str) and raw else None
            packaged=folder/name;old=old_folder/name
            path=next((p for p in (selected,packaged,old) if p is not None and p.is_file() and p.suffix.lower() in {'.ckl','.xml'}),None)
            found[platform][choice]=str(path.resolve()) if path else ''
    return found


def persist_template_paths(choices:dict[str,dict[str,str]],folder:Path,settings:Path)->None:
    saved={};folder=folder.resolve()
    for platform,entries in choices.items():
        saved[platform]={}
        for choice,raw in entries.items():
            if not raw.strip():continue
            path=Path(raw).expanduser().resolve()
            if not path.is_file() or path.suffix.lower() not in {'.ckl','.xml'}:raise ValueError(f'Choose an existing CKL or XML template: {path}')
            try:saved[platform][choice]='project:'+path.relative_to(folder).as_posix()
            except ValueError:saved[platform][choice]=str(path)
    settings.parent.mkdir(parents=True,exist_ok=True)
    temp=settings.with_suffix(settings.suffix+'.tmp')
    temp.write_text(json.dumps(saved,indent=2)+'\n',encoding='utf-8');temp.replace(settings)


def family_results(results: list, family: str) -> list:
    """Select results for one check library regardless of STIG label case."""
    return [result for result in results if result.stig_family.casefold() == family.casefold()]

def parse_device_text(text: str) -> tuple[list[str], list[str]]:
    valid, problems, seen = [], [], set()
    for row, raw in enumerate(re.split(r"[\r\n,;\t]+", text), 1):
        value = raw.strip()
        if not value: continue
        try: ipaddress.ip_address(value); okay = True
        except ValueError: okay = bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", value))
        if not okay: problems.append(f"Row {row}: invalid address '{value}'")
        elif value.casefold() in seen: problems.append(f"Row {row}: duplicate '{value}'")
        else: seen.add(value.casefold()); valid.append(value)
    return valid, problems

def parse_device_file(path: str | Path) -> tuple[list[str], list[str]]:
    p = Path(path)
    if p.suffix.lower() == ".csv":
        with p.open(encoding="utf-8-sig", newline="") as f: rows = list(csv.reader(f))
        if not rows: return [], ["The file is empty."]
        headers = [x.strip().casefold() for x in rows[0]]
        header = next((x for x in ("ip", "address", "host", "hostname") if x in headers), None)
        idx = headers.index(header) if header else 0
        data_rows = rows[1:] if header else rows
        return parse_device_text("\n".join(r[idx] for r in data_rows if len(r) > idx))
    return parse_device_text(p.read_text(encoding="utf-8-sig"))

def sample_outputs(target: DeviceTargetRecord) -> dict[str, str]:
    root = Path(__file__).resolve().parents[1] / "tests" / "sample_outputs"
    folder = root / ("noncompliant" if target.ip.split(".")[-1:] == ["26"] else "compliant")
    return {c: (folder / f).read_text(encoding="utf-8", errors="replace") for c, f in COMMAND_FILES.items() if (folder / f).exists()}

def report_stem(asset, scan_ip: str, families: list[str], when: datetime | None = None) -> str:
    """Build the operator-facing filename stem requested for Basic reports."""
    # The scan target is unique in a licensed batch. Discovered management
    # addresses and final IP octets are not, so they cannot identify a file.
    try:
        address = str(ipaddress.ip_address(scan_ip))
        short = address.split(".")[-1] if "." in address else "ipv6"
    except ValueError:
        address = scan_ip.rstrip(".").casefold()
        short = "device"
    safe_address = re.sub(r"[^A-Za-z0-9]+", "-", address).strip("-")[:48] or "device"
    target_id = f"{safe_address}-{hashlib.sha256(address.encode('utf-8')).hexdigest()[:12]}"
    platform = "IOSXE" if all(f.startswith("iosxe_") for f in families) else "IOS"
    label = "_".join(f.rsplit("_", 1)[-1].upper() for f in families)
    date_text = (when or datetime.now()).strftime("%d%b%Y").upper()
    return f"{short}_{platform}_{label}_{date_text}_{target_id}"


def _failed_outcome_text(outcome) -> str:
    """Give operators actionable failures without echoing raw SSH exceptions."""
    message = (outcome.error_message or "").casefold()
    if outcome.status.value == "AUTH_FAILED":
        reason = "SSH authentication failed; check the account and credentials"
    elif outcome.status.value == "CONNECT_FAILED":
        reason = "SSH connection failed; check the address, port, and reachability"
    elif outcome.status.value == "CANCELLED":
        reason = "Cancelled before a complete assessment"
    elif outcome.status.value == "EVALUATION_FAILED":
        reason = "Assessment evaluation failed; review the selected checks and profile"
    else:
        reason = "Collection failed; check device access, SSH settings, and reachability"
    return f"{outcome.target_ip}: {reason}"


def _scan_event_text(event) -> str:
    """Render live progress without displaying untrusted device/SSH errors."""
    status = str(event.status)
    if status in {"AUTH_FAILED", "CONNECT_FAILED", "COLLECTION_FAILED", "EVALUATION_FAILED", "CANCELLED"}:
        return _failed_outcome_text(SimpleNamespace(
            target_ip=event.target_ip,
            status=SimpleNamespace(value=status),
            error_message=event.message,
        ))
    target = f"{event.target_ip}: " if event.target_ip else ""
    label = status.replace("_", " ").title()
    progress = f" ({event.completed}/{event.total})" if event.total and event.completed else ""
    return f"{target}{label}{progress}"

class BasicApp:
    def __init__(self, root, vault: AtRestVault):
        import customtkinter as ctk
        from tkinter import filedialog, messagebox
        from platformdirs import user_documents_dir
        self.root, self.ctk, self.filedialog, self.messagebox = root, ctk, filedialog, messagebox
        self.events, self.cancel_event, self.thread = queue.Queue(), threading.Event(), None
        self.last_results,self.last_targets,self.last_families,self.last_run_id=[],[],[],''
        self.last_report_paths, self.last_output_dir = [], None
        self.license_policy = BasicLicensePolicy()
        self.artifacts = ProtectedArtifactStore(vault)
        self.build_metadata = load_build_metadata()
        self.selected_addresses = ['192.0.2.10']
        self.selection_dialog = None
        self.project_root = Path(user_documents_dir()) / "STIG Audit Pro Basic"
        self.workspace = self.project_root / "Workspace"
        self.package_templates=(Path(sys.executable).resolve().parent.parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parents[1])/'Checklist Templates'
        self.template_settings=self.workspace/'template_paths.json'
        for n in ("CKL Templates", "Completed CKLs", "Reports", "Device Imports"): (self.workspace / n).mkdir(parents=True, exist_ok=True)
        bundle_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
        bundled = bundle_root / "data"
        if not bundled.is_dir(): bundled = bundle_root / "_internal" / "data"
        # One canonical editable folder: beside the executable when packaged,
        # or Source/data during development. No hidden AppData copy is used.
        self.data_root = (Path(sys.executable).resolve().parent / "data") if getattr(sys, "frozen", False) else (Path(__file__).resolve().parents[1] / "data")
        self.data_root.mkdir(parents=True, exist_ok=True)
        for item in bundled.rglob("*"):
            if item.is_file():
                destination = self.data_root / item.relative_to(bundled)
                destination.parent.mkdir(parents=True, exist_ok=True)
                if not destination.exists(): shutil.copy2(item, destination)
        self.device_group_store = DeviceGroupStore(self.data_root / "device_groups")
        self._build()
        self.refresh_license_status()
        self._license_timer = self.root.after(30000, self.check_license_timer)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build(self):
        ctk = self.ctk
        ctk.set_appearance_mode("dark")
        colors = {
            "background": "#0B1627", "card": "#14243A", "raised": "#1D314A",
            "border": "#2B4562", "text": "#F2F7FC", "muted": "#B4C7D9",
            "teal": "#21C6B7", "teal_hover": "#16A89B", "blue": "#377BE8",
            "amber": "#F2BD63", "red": "#F08989",
        }
        self.colors = colors
        self.root.title("STIG Audit Pro Basic — Read-Only Switch Audit")
        self.root.geometry("1080x800")
        self.root.minsize(960, 680)
        self.root.configure(fg_color=colors["background"])

        header = ctk.CTkFrame(self.root, fg_color=colors["background"])
        header.pack(fill="x", padx=24, pady=(18, 2))
        title = ctk.CTkFrame(header, fg_color="transparent")
        title.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(title, text="STIG AUDIT  /  BASIC", text_color=colors["teal"],
                     font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(title, text="Switch compliance, clearly evidenced",
                     text_color=colors["text"], font=ctk.CTkFont(size=25, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(title, text="Read-only collection  •  protected reports  •  operator-controlled export",
                     text_color=colors["muted"]).pack(anchor="w")
        ctk.CTkLabel(
            title,
            text=(
                f"Build updated {self.build_metadata['date']}  •  "
                f"v{self.build_metadata['version']}  •  {self.build_metadata['id']}"
            ),
            text_color=colors["muted"],
            font=ctk.CTkFont(size=11),
        ).pack(anchor="w", pady=(3, 0))
        ctk.CTkLabel(header, text="READ ONLY  ·  ENCRYPTED OUTPUT", text_color=colors["teal"],
                     fg_color=colors["card"], corner_radius=10, padx=14, pady=9,
                     font=ctk.CTkFont(size=12, weight="bold")).pack(side="right", anchor="n", pady=6)

        tabs = ctk.CTkTabview(
            self.root, fg_color=colors["background"],
            segmented_button_fg_color=colors["card"],
            segmented_button_selected_color=colors["blue"],
            segmented_button_unselected_color=colors["card"],
            text_color=colors["text"],
        )
        tabs.pack(fill="both", expand=True, padx=18, pady=(4, 12))
        self.tabs = tabs
        audit_tab = tabs.add("Audit")
        audit = ctk.CTkScrollableFrame(audit_tab, fg_color=colors["background"])
        audit.pack(fill="both", expand=True)
        result = tabs.add("Results")
        summary = tabs.add("Summary")
        license_tab = tabs.add("License")
        help_ = tabs.add("Help")
        setup_tab = tabs.add("Profiles & Sites")
        self._build_summary(summary)

        from stig_audit_pro.gui.basic_license_ui import BasicLicensePanel
        self.license_panel = BasicLicensePanel(license_tab, self.import_license_file, self.refresh_license_status)
        self.license_panel.pack(fill="both", expand=True)

        ctk.CTkLabel(result, text="Protected report workspace", text_color=colors["text"],
                     font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=16, pady=(14, 2))
        ctk.CTkLabel(result, text="View text in memory. Export creates a readable file on disk only when you choose it.",
                     text_color=colors["muted"]).pack(anchor="w", padx=16)
        protected_row = ctk.CTkFrame(result, fg_color=colors["card"], corner_radius=10)
        protected_row.pack(fill="x", padx=12, pady=(12, 0))
        ctk.CTkButton(protected_row, text="Open protected report folder", command=self.open_protected_report,
                      fg_color=colors["blue"]).pack(side="left", padx=8, pady=8)
        ctk.CTkButton(protected_row, text="Export readable copy", command=self.export_protected_report,
                      fg_color=colors["raised"], hover_color=colors["border"]).pack(side="left", padx=4, pady=8)
        self.results_box = ctk.CTkTextbox(result, fg_color=colors["card"], text_color=colors["text"])
        self.results_box.pack(fill="both", expand=True, padx=12, pady=12)

        help_text = (
            "1. Paste device IPs or import CSV/TXT, then choose Select devices. Free Basic runs one device per audit.\n"
            "2. Choose IOS XE or IOS, a STIG family, and an approved site profile.\n"
            "3. For Live SSH, confirm the device address, port, and account before starting.\n"
            "4. Choose a matching blank CKL template if you want checklist output.\n"
            "5. Start the audit. The run card shows the encrypted file count and exact output folder.\n"
            "6. Open the protected report folder in Results, or explicitly export an unencrypted copy.\n\n"
            "Live SSH verifies device host keys by default. You may disable verification for a controlled compatibility test, but that removes protection against connecting to an impersonated device. Audit and summary files use .sapenc.\n"
            "Credentials and the audit-data passphrase are not saved by the app; SSH credentials remain in memory during a live run.\n"
            "Editable checks and profiles are beside the application in data. Review starter checks against the approved benchmark."
        )
        ctk.CTkLabel(help_, justify="left", anchor="w", text=help_text,
                     text_color=colors["muted"], wraplength=900).pack(anchor="nw", padx=18, pady=18)

        targets_card = self._audit_card(audit, "01  TARGETS", "Keep a device list and select the current licensed batch.")
        self.devices = ctk.CTkTextbox(targets_card, height=84, fg_color=colors["raised"])
        self.devices.pack(fill="x", padx=14, pady=(8, 6))
        self.devices.insert("1.0", "192.0.2.10\n")
        self.devices.bind("<KeyRelease>", lambda _: self.sync_selected_devices())
        selection_row = ctk.CTkFrame(targets_card, fg_color="transparent")
        selection_row.pack(fill="x", padx=10, pady=(0, 10))
        ctk.CTkButton(selection_row, text="Select devices", command=self.select_devices,
                      fg_color=colors["blue"]).pack(side="left", padx=4)
        ctk.CTkButton(selection_row, text="Import CSV/TXT", command=self.import_devices,
                      fg_color=colors["raised"], hover_color=colors["border"]).pack(side="left", padx=4)
        self.selection_label = ctk.CTkLabel(selection_row, text="", justify="left", anchor="w",
                                            wraplength=580, text_color=colors["muted"])
        self.selection_label.pack(side="left", fill="x", expand=True, padx=10)

        group_row = ctk.CTkFrame(targets_card, fg_color=colors["raised"], corner_radius=8)
        group_row.pack(fill="x", padx=14, pady=(0, 10))
        ctk.CTkLabel(group_row, text="Saved building", width=120, anchor="w",
                     text_color=colors["muted"]).pack(side="left", padx=8, pady=8)
        self.saved_group = ctk.CTkOptionMenu(
            group_row,
            values=["Manual device list"] + self._group_names(),
            command=self.apply_saved_group,
        )
        self.saved_group.pack(side="left", fill="x", expand=True, padx=4, pady=8)
        self.saved_group.set("Manual device list")
        self.saved_group_summary = ctk.CTkLabel(
            group_row, text="Choose a saved building to load its devices and profile.",
            anchor="w", text_color=colors["muted"], wraplength=430,
        )
        self.saved_group_summary.pack(side="left", fill="x", expand=True, padx=8)

        setup_card = self._audit_card(audit, "02  AUDIT SETUP", "Choose the platform, STIG family, mode, and site profile.")
        row = ctk.CTkFrame(setup_card, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=(8, 5))
        self.platform = ctk.CTkOptionMenu(row, values=["IOS XE", "IOS"], command=self.on_platform_change)
        self.platform.pack(side="left", padx=4)
        self.platform.set("IOS XE")
        self.family = ctk.CTkOptionMenu(row, values=["L2", "NDM", "L2 + NDM"], command=lambda _: self.update_paths())
        self.family.pack(side="left", padx=4)
        self.mode = ctk.CTkOptionMenu(row, values=["Sample outputs", "Live SSH"], command=lambda _: self.update_mode_badge())
        self.mode.pack(side="left", padx=4)
        self.profile = ctk.CTkOptionMenu(row, values=self._profiles(), command=lambda _: self.update_paths())
        self.profile.pack(side="left", padx=4)
        self.profile.set(default_profile_name("IOS XE"))
        self.mode_badge = ctk.CTkLabel(setup_card, text="", anchor="w",
                                       font=ctk.CTkFont(size=12, weight="bold"))
        self.mode_badge.pack(fill="x", padx=16, pady=(2, 2))
        self.update_mode_badge()
        self.path_label = ctk.CTkLabel(setup_card, justify="left", anchor="w", text="",
                                       wraplength=940, text_color=colors["muted"])
        self.path_label.pack(fill="x", padx=16, pady=(0, 6))
        self.update_paths()
        cred = ctk.CTkFrame(setup_card, fg_color="transparent")
        cred.pack(fill="x", padx=10, pady=(0, 12))
        self.user = ctk.CTkEntry(cred, placeholder_text="SSH username")
        self.user.pack(side="left", fill="x", expand=True, padx=4)
        self.password = ctk.CTkEntry(cred, placeholder_text="SSH password", show="•")
        self.password.pack(side="left", fill="x", expand=True, padx=4)
        self.secret = ctk.CTkEntry(cred, placeholder_text="Enable secret (optional)", show="•")
        self.secret.pack(side="left", fill="x", expand=True, padx=4)
        self.verify_host_keys = ctk.BooleanVar(value=True)
        self.host_key_check = ctk.CTkCheckBox(
            setup_card,
            text="Verify SSH host keys (recommended)",
            variable=self.verify_host_keys,
            command=self.update_mode_badge,
            text_color=colors["text"],
            hover_color=colors["blue"],
        )
        self.host_key_check.pack(anchor="w", padx=16, pady=(0, 10))

        template_card = self._audit_card(audit, "03  BLANK CHECKLIST TEMPLATES", "Assign each platform its own approved CKL template.")
        self.template_tabs = ctk.CTkTabview(template_card, height=170, fg_color=colors["card"])
        self.template_tabs.pack(fill="x", padx=10, pady=(0, 10))
        self.template_entries={}
        for platform_name in ("IOS XE", "IOS"):
            template_tab=self.template_tabs.add(platform_name)
            self.template_entries[platform_name]={}
            for choice in ("L2", "NDM", "L2 + NDM"):
                template_row=ctk.CTkFrame(template_tab,fg_color="transparent"); template_row.pack(fill="x",padx=4,pady=2)
                ctk.CTkLabel(template_row,text=choice,width=85).pack(side="left",padx=4)
                entry=ctk.CTkEntry(template_row,placeholder_text=f"{platform_name} {choice} blank CKL template")
                entry.pack(side="left",fill="x",expand=True,padx=4)
                ctk.CTkButton(template_row,text="Browse",width=85,command=lambda selected=entry,p=platform_name,c=choice:self.browse_template(selected,p,c)).pack(side="left",padx=4)
                self.template_entries[platform_name][choice]=entry
        for platform_name, choices in load_template_paths(self.package_templates,self.workspace / "CKL Templates",self.template_settings).items():
            for choice, path in choices.items():
                if path: self.template_entries[platform_name][choice].insert(0, path)
        self.template_tabs.set("IOS XE")

        output_card = self._audit_card(audit, "04  PROTECTED OUTPUT", "Reports are encrypted in memory before they reach disk.")
        out = ctk.CTkFrame(output_card, fg_color="transparent")
        out.pack(fill="x", padx=10, pady=(8, 2))
        self.output_dir = ctk.CTkEntry(out)
        self.output_dir.pack(side="left", fill="x", expand=True, padx=4)
        self.output_dir.insert(0, str(self.workspace / "Completed CKLs"))
        self.output_dir.bind("<KeyRelease>", lambda _: self.update_output_hint())
        ctk.CTkButton(out, text="Choose output folder", command=self.browse_output,
                      fg_color=colors["raised"], hover_color=colors["border"]).pack(side="left", padx=4)
        self.output_hint = ctk.CTkLabel(output_card, text="", anchor="w", text_color=colors["muted"])
        self.output_hint.pack(fill="x", padx=16)
        self.update_output_hint()
        formats = ctk.CTkFrame(output_card, fg_color="transparent")
        formats.pack(fill="x", padx=10, pady=(2, 10))
        ctk.CTkLabel(formats, text="Create:", text_color=colors["muted"]).pack(side="left", padx=4)
        self.txt_var = ctk.BooleanVar(value=True)
        self.ckl_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(formats, text="TXT report", variable=self.txt_var).pack(side="left", padx=8)
        ctk.CTkCheckBox(formats, text="CKL checklist", variable=self.ckl_var).pack(side="left", padx=8)

        run_card = self._audit_card(audit, "05  RUN & REVIEW", "Follow progress and confirm the exact saved files.")
        actions = ctk.CTkFrame(run_card, fg_color="transparent")
        actions.pack(fill="x", padx=10, pady=(8, 4))
        ctk.CTkButton(actions, text="Start audit", command=self.start, fg_color=colors["teal"],
                      hover_color=colors["teal_hover"], text_color=colors["background"],
                      font=ctk.CTkFont(weight="bold")).pack(side="left", padx=4)
        ctk.CTkButton(actions, text="Cancel run", command=self.cancel_run,
                      fg_color=colors["raised"], hover_color=colors["border"]).pack(side="left", padx=4)
        self.status = ctk.CTkLabel(actions, text="Ready", anchor="w", text_color=colors["muted"])
        self.status.pack(side="left", fill="x", expand=True, padx=12)
        result_card = ctk.CTkFrame(run_card, fg_color=colors["raised"], corner_radius=10)
        result_card.pack(fill="x", padx=14, pady=(4, 14))
        self.run_state_label = ctk.CTkLabel(result_card, text="NO RUN YET", anchor="w",
                                            text_color=colors["muted"], font=ctk.CTkFont(size=14, weight="bold"))
        self.run_state_label.pack(fill="x", padx=14, pady=(12, 0))
        self.run_counts_label = ctk.CTkLabel(result_card, text="0 protected files  ·  0 failed devices", anchor="w",
                                             text_color=colors["text"])
        self.run_counts_label.pack(fill="x", padx=14)
        self.run_folder_label = ctk.CTkLabel(result_card, text="Output folder: no run yet", anchor="w",
                                             text_color=colors["muted"], wraplength=900)
        self.run_folder_label.pack(fill="x", padx=14, pady=(0, 4))
        result_actions = ctk.CTkFrame(result_card, fg_color="transparent")
        result_actions.pack(fill="x", padx=10, pady=(0, 10))
        self.open_folder_button = ctk.CTkButton(result_actions, text="Open output folder", state="disabled",
                                                 command=self.open_output_folder, fg_color=colors["blue"])
        self.open_folder_button.pack(side="left", padx=4)
        self.view_latest_button = ctk.CTkButton(result_actions, text="View latest protected report", state="disabled",
                                                 command=self.view_latest_protected_report,
                                                 fg_color=colors["card"])
        self.view_latest_button.pack(side="left", padx=4)

        from stig_audit_pro.gui.site_setup import SiteSetupPanel

        self.site_setup_panel = SiteSetupPanel(
            setup_tab,
            profiles_dir=self.data_root / "profiles",
            groups_dir=self.data_root / "device_groups",
            on_profiles_changed=self.refresh_profile_controls,
            on_group_saved=self.refresh_group_controls,
        )

    def _audit_card(self, parent, title: str, subtitle: str):
        ctk = self.ctk
        card = ctk.CTkFrame(parent, fg_color=self.colors["card"], corner_radius=12,
                            border_width=1, border_color=self.colors["border"])
        card.pack(fill="x", padx=12, pady=7)
        ctk.CTkLabel(card, text=title, anchor="w", text_color=self.colors["teal"],
                     font=ctk.CTkFont(size=13, weight="bold")).pack(fill="x", padx=14, pady=(11, 0))
        ctk.CTkLabel(card, text=subtitle, anchor="w", text_color=self.colors["muted"]).pack(fill="x", padx=14)
        return card

    def update_mode_badge(self):
        live = self.mode.get() == "Live SSH"
        checking = bool(self.verify_host_keys.get()) if hasattr(self, "verify_host_keys") else True
        label = (("LIVE SSH  ·  host-key verification enabled  ·  network device access" if checking
                  else "LIVE SSH  ·  host-key verification DISABLED  ·  compatibility mode") if live
                 else "DEMO MODE  ·  bundled IOS XE evidence  ·  no device connection")
        self.mode_badge.configure(text=label, text_color=(self.colors["amber"] if live else self.colors["teal"]))

    def update_output_hint(self):
        self.output_hint.configure(text=f"Encrypted .sapenc files will be saved in: {self.output_dir.get().strip() or '[choose folder]'}")

    def _build_summary(self,tab):
        ctk=self.ctk
        ctk.CTkLabel(tab,text='Combined summary for the current audit run',text_color=self.colors['text'],font=ctk.CTkFont(size=18,weight='bold')).pack(anchor='w',padx=12,pady=(12,2))
        ctk.CTkLabel(tab,text='Filter findings, preview, then save encrypted PDF, HTML, or CSV.',text_color=self.colors['muted'],wraplength=820).pack(anchor='w',padx=12)
        row=ctk.CTkFrame(tab,fg_color=self.colors['card']);row.pack(fill='x',padx=12,pady=8)
        self.summary_status=ctk.CTkOptionMenu(row,values=['All results','Open only','Not a Finding only','Needs review','Errors only','Skipped only','Not Applicable only','Not Reviewed only']);self.summary_status.pack(side='left',padx=3);self.summary_status.set('All results')
        self.summary_cat=ctk.CTkOptionMenu(row,values=['All CATs','CAT I','CAT II','CAT III','Other']);self.summary_cat.pack(side='left',padx=3);self.summary_cat.set('All CATs')
        self.summary_device=ctk.CTkOptionMenu(row,values=['All devices']);self.summary_device.pack(side='left',padx=3);self.summary_device.set('All devices')
        self.summary_family=ctk.CTkOptionMenu(row,values=['All families']);self.summary_family.pack(side='left',padx=3);self.summary_family.set('All families')
        row=ctk.CTkFrame(tab,fg_color=self.colors['card']);row.pack(fill='x',padx=12,pady=4)
        self.summary_pdf=ctk.BooleanVar(value=True);self.summary_html=ctk.BooleanVar(value=True);self.summary_csv=ctk.BooleanVar(value=True)
        for label,var in [('PDF with charts',self.summary_pdf),('HTML with charts',self.summary_html),('CSV details',self.summary_csv)]:ctk.CTkCheckBox(row,text=label,variable=var).pack(side='left',padx=8,pady=5)
        ctk.CTkButton(row,text='Export summary',command=self.export_summary).pack(side='right',padx=5)
        ctk.CTkButton(row,text='Preview',command=self.preview_summary).pack(side='right',padx=5)
        self.summary_box=ctk.CTkTextbox(tab,fg_color=self.colors['card'],text_color=self.colors['text']);self.summary_box.pack(fill='both',expand=True,padx=12,pady=8);self.summary_box.insert('1.0','Run an audit first. The summary covers only devices in that run.')

    def _summary_filter(self):
        groups={'All results':frozenset(STATUSES),'Open only':frozenset({'Open'}),'Not a Finding only':frozenset({'NotAFinding'}),
                'Needs review':frozenset({'Open','Error','Skipped','Not_Reviewed'}),'Errors only':frozenset({'Error'}),
                'Skipped only':frozenset({'Skipped'}),'Not Applicable only':frozenset({'Not_Applicable'}),'Not Reviewed only':frozenset({'Not_Reviewed'})}
        selected=self.summary_cat.get();device=self.summary_device.get();family=self.summary_family.get()
        return Filter(statuses=groups[self.summary_status.get()],cats=frozenset(CATS) if selected=='All CATs' else frozenset({selected}),
                      devices=None if device=='All devices' else frozenset({device}),families=None if family=='All families' else frozenset({family}))

    def preview_summary(self):
        self.summary_box.delete('1.0','end')
        if not self.last_targets:self.summary_box.insert('end','Run an audit first.');return
        report=summarize(self.last_results,self._summary_filter(),self.last_targets)
        lines=[f"CURRENT RUN: {report['devices']} devices; {report['checks']} check results",
               f"Open {report['status']['Open']} | Not a Finding {report['status']['NotAFinding']} | Error {report['status']['Error']} | Not Reviewed {report['status']['Not_Reviewed']}",
               f"Assessed pass rate: {report['pass_rate']}% | Assessment coverage: {report['coverage']}%",
               'Devices without check results: '+(', '.join(report['unassessed']) or 'None'),'',
               f"FILTERED DETAIL: {len(report['details'])} matching results",'','OPEN BY SWITCH:']
        for ip,counts in report['open_by_device'].items():lines.append(f"  {ip}: CAT I {counts['CAT I']} | CAT II {counts['CAT II']} | CAT III {counts['CAT III']}")
        lines.extend(['','FIRST 100 MATCHING RESULTS:'])
        lines.extend(f'{r.ip} | {r.vuln_id} | {cat(r.severity)} | {r.status} | {r.title}' for r in report['details'][:100])
        self.summary_box.insert('end','\n'.join(lines))

    def export_summary(self):
        if not self.last_targets:self.messagebox.showerror('No audit results','Run an audit first.');return []
        choices=[('pdf',self.summary_pdf.get(),render_pdf),('html',self.summary_html.get(),render_html),('csv',self.summary_csv.get(),render_csv)]
        if not any(enabled for _,enabled,_ in choices):self.messagebox.showerror('Choose format','Select PDF, HTML, or CSV.');return []
        paths=[]
        try:
            self.license_policy.validate(self.last_targets,self.last_families,True,False)
            report=summarize(self.last_results,self._summary_filter(),self.last_targets)
            folder=Path(self.output_dir.get()).expanduser();folder.mkdir(parents=True,exist_ok=True)
            stem='OVERALL_SUMMARY_'+self.last_run_id[:8]+'_'+datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            for ext,enabled,writer in choices:
                if enabled:
                    paths.append(self.artifacts.save(folder/f'{stem}.{ext}',writer(report)))
        except Exception as exc:
            logging.getLogger(__name__).exception('Basic summary export failed')
            detail=f'Summary export stopped ({type(exc).__name__}). {len(paths)} encrypted file(s) saved.'
            if paths:detail+='\n'+'\n'.join(str(path) for path in paths)
            self.messagebox.showerror('Summary export incomplete',detail)
            return paths
        self.preview_summary();self.messagebox.showinfo('Protected summary saved','Encrypted files created:\n'+'\n'.join(str(p) for p in paths));return paths

    def _profiles(self): return [p.stem for p in sorted((self.data_root/"profiles").glob("*.yaml"))] or ["base_iosxe_access"]
    def _group_names(self):
        return self.device_group_store.list_groups()

    def refresh_profile_controls(self):
        values = self._profiles()
        current = self.profile.get()
        self.profile.configure(values=values)
        if current not in values:
            self.profile.set(default_profile_name(self.platform.get()))
        self.update_paths()

    def refresh_group_controls(self, selected: str | None = None):
        values = ["Manual device list"] + self._group_names()
        self.saved_group.configure(values=values)
        if selected and selected in values:
            self.saved_group.set(selected)

    def apply_saved_group(self, name: str):
        if name == "Manual device list":
            self.saved_group_summary.configure(text="Manual device list selected. Enter devices above.")
            return
        try:
            group = self.device_group_store.load_group(name)
            addresses, profile_name = selected_group_values(group)
            if not addresses:
                raise ValueError("The saved group has no checked devices")
            self.devices.delete("1.0", "end")
            self.devices.insert("1.0", "\n".join(addresses))
            self.selected_addresses = list(addresses)
            if profile_name and profile_name in self._profiles():
                self.profile.set(profile_name)
            self.sync_selected_devices()
            self.update_paths()
            self.saved_group_summary.configure(
                text=f"{len(addresses)} device(s) · profile {profile_name or '[none]'}"
            )
        except (OSError, ValueError) as exc:
            self.saved_group_summary.configure(text="Could not load saved building")
            self.messagebox.showerror("Saved building unavailable", str(exc))
    def sync_selected_devices(self):
        addresses,_=parse_device_text(self.devices.get('1.0','end'))
        addresses=list(normalize_basic_targets(addresses))
        self.selected_addresses=[a for a in self.selected_addresses if a in addresses]
        limit=self.license_policy.device_limit
        summary=f'{len(self.selected_addresses)} selected / {len(addresses)} listed — limit {limit} per audit'
        if len(self.selected_addresses)==1:summary+='\n'+self.selected_addresses[0]
        self.selection_label.configure(text=summary)
        return addresses
    def select_devices(self):
        if self.selection_dialog is not None and self.selection_dialog.winfo_exists():
            self.selection_dialog.lift();return
        self.refresh_license_status()
        addresses=self.sync_selected_devices()
        if not addresses:self.messagebox.showerror('No devices','Add device addresses to the list first.');return
        from stig_audit_pro.gui.basic_license_ui import DeviceSelectionDialog
        self.selection_dialog=DeviceSelectionDialog(self.root,addresses,self.selected_addresses,self.license_policy.device_limit,self.apply_device_selection)
    def apply_device_selection(self, selected):
        self.selected_addresses=list(selected)
        self.sync_selected_devices()
    def refresh_license_status(self):
        self.license_policy.refresh()
        self.license_panel.refresh(self.license_policy)
        self.sync_selected_devices()
    def check_license_timer(self):
        self.refresh_license_status()
        self._license_timer=self.root.after(30000,self.check_license_timer)
    def import_license_file(self):
        if self.thread and self.thread.is_alive():
            self.messagebox.showinfo('Audit running','Wait for the current audit to finish before replacing the license.');return
        path=self.filedialog.askopenfilename(title='Import Basic license',filetypes=[('Signed license','*.license.json'),('JSON','*.json')])
        if not path:return
        try:self.license_policy.import_license(path)
        except (LicenseImportError,OSError) as exc:self.messagebox.showerror('License not imported',str(exc));return
        self.refresh_license_status()
        self.messagebox.showinfo('License imported','The signed license is installed. Use Select devices to choose your audit batch.')
    def open_protected_report(self):
        self.open_output_folder()

    def _display_protected_report(self, selected):
        try:
            content=self.artifacts.read(selected)
            original_name=Path(selected).stem
            if Path(original_name).suffix.lower()=='.pdf':
                self.messagebox.showinfo('Protected PDF',f'{original_name} was verified and decrypted in memory. Use Export readable copy to open it in a PDF viewer.')
                return
            preview=content[:2_000_000].decode('utf-8-sig',errors='replace')
            if len(content)>2_000_000:preview+='\n\n[Preview limited to the first 2 MB]'
            self.results_box.delete('1.0','end');self.results_box.insert('end',preview)
            if hasattr(self, 'tabs'): self.tabs.set('Results')
        except (OSError,ValueError) as exc:self.messagebox.showerror('Could not open protected report',str(exc))

    def view_latest_protected_report(self):
        for path in reversed(self.last_report_paths):
            if Path(path).is_file() and '.txt.sapenc' in Path(path).name.lower():
                self._display_protected_report(path)
                return
        if self.last_report_paths:
            self._display_protected_report(self.last_report_paths[-1])
        else:
            self.messagebox.showinfo('No report yet', 'This run did not create a protected report.')

    def open_output_folder(self):
        folder = self.last_output_dir
        if folder is None or not Path(folder).is_dir():
            self.messagebox.showinfo('No output folder', 'Run an audit first or choose an existing output folder.')
            return
        try:
            os.startfile(str(folder))
        except OSError as exc:
            self.messagebox.showerror('Could not open output folder', f'{type(exc).__name__}: {folder}')
    def export_protected_report(self):
        selected=self.filedialog.askopenfilename(title='Select protected Basic report',filetypes=[('Protected Basic report','*.sapenc')])
        if not selected:return
        original_name=Path(selected).stem
        destination=self.filedialog.asksaveasfilename(title='Export readable copy',initialfile=original_name,defaultextension=Path(original_name).suffix)
        if not destination:return
        if not self.messagebox.askyesno('Export readable report','This creates an unencrypted file that other applications can read. Continue?'):return
        try:self.artifacts.export(selected,destination)
        except (OSError,ValueError) as exc:self.messagebox.showerror('Export failed',str(exc));return
        self.messagebox.showinfo('Readable copy exported',destination)
    def on_platform_change(self, platform):
        self.profile.set(default_profile_name(platform))
        self.template_tabs.set(platform)
        self.update_paths()
    def update_paths(self):
        check_paths = [self.data_root / "checks" / f"{name}.yaml" for name in library_names(self.platform.get(), self.family.get())]
        self.path_label.configure(text=f"Check file(s): {', '.join(str(path) for path in check_paths)}\nSite profile: {self.data_root / 'profiles' / (self.profile.get() + '.yaml')}\nEditable data folder: {self.data_root}")
    def browse_template(self,e,platform,choice):
        p=self.filedialog.askopenfilename(initialdir=str(self.package_templates),filetypes=[("CKL/XML","*.ckl *.xml"),("All files","*.*")]);
        if not p:return
        selected=Path(p).expanduser().resolve()
        if not selected.is_file() or selected.suffix.lower() not in {'.ckl','.xml'}:
            self.messagebox.showerror('Invalid template',str(selected));return
        previous=e.get();e.delete(0,'end');e.insert(0,str(selected))
        try:self.store_template_entries()
        except (OSError,ValueError) as exc:
            e.delete(0,'end');e.insert(0,previous);self.messagebox.showerror('Template could not be saved',str(exc))
    def store_template_entries(self):
        persist_template_paths({p:{c:e.get().strip() for c,e in entries.items()} for p,entries in self.template_entries.items()},self.package_templates,self.template_settings)
    def on_close(self):
        if self.thread and self.thread.is_alive():
            self.cancel_event.set()
            self.status.configure(text='Cancelling audit; the window can close after the current save finishes.')
            self.messagebox.showinfo('Audit still running', 'Cancellation requested. Wait for the current device and report save to finish, then close the window.')
            return
        if getattr(self,'_license_timer',None):self.root.after_cancel(self._license_timer)
        try:self.store_template_entries()
        except (OSError,ValueError):pass
        self.root.destroy()

    def cancel_run(self):
        if self.thread and self.thread.is_alive():
            self.cancel_event.set()
            self.status.configure(text='Cancellation requested; waiting for active device work.')

    def browse_output(self):
        p=self.filedialog.askdirectory()
        if p:
            self.output_dir.delete(0,"end")
            self.output_dir.insert(0,p)
            self.update_output_hint()

    def _take_ssh_credentials(self):
        credentials = DeviceCredentials(
            username=self.user.get(),
            password=self.password.get(),
            secret=self.secret.get() or None,
        )
        self.password.delete(0, 'end')
        self.secret.delete(0, 'end')
        return credentials
    def import_devices(self):
        p=self.filedialog.askopenfilename(filetypes=[("Device list","*.csv *.txt"),("All files","*.*")]);
        if not p:return
        try:v,issues=parse_device_file(p)
        except Exception as exc:self.messagebox.showerror("Import failed",str(exc));return
        self.devices.delete("1.0","end");self.devices.insert("1.0","\n".join(v));self.sync_selected_devices();self.messagebox.showwarning("Import review",f"{len(v)} valid devices.\n"+("\n".join(issues) if issues else "No problems found."))
    def start(self):
        if self.thread and self.thread.is_alive():return
        self.refresh_license_status()
        addresses=list(self.selected_addresses)
        if not addresses:self.messagebox.showerror("No devices selected","Use Select devices to choose at least one device from your list.");return
        platform = self.platform.get()
        families = library_names(platform, self.family.get())
        if self.mode.get() == "Sample outputs" and not can_use_sample_outputs(platform):
            self.messagebox.showerror("IOS sample output unavailable", "The bundled sample output is from IOS XE switches. Choose Live SSH for an IOS switch."); return
        try:
            checks=[]
            for f in families:checks.extend(load_check_library(self.data_root/"checks"/f"{f}.yaml").checks)
            profile=load_profile(self.data_root/"profiles"/f"{self.profile.get()}.yaml",profiles_dir=self.data_root/"profiles")
        except (ConfigValidationError,OSError) as exc:self.messagebox.showerror("Configuration not ready",str(exc));return
        make_txt, make_ckl = bool(self.txt_var.get()), bool(self.ckl_var.get())
        if not make_txt and not make_ckl: self.messagebox.showerror("Choose an output", "Select TXT report, CKL checklist, or both."); return
        try:addresses=list(self.license_policy.validate(addresses,families,make_txt,make_ckl))
        except LicensePolicyError as exc:self.messagebox.showerror('License limit',str(exc));return
        try:self.store_template_entries()
        except (OSError,ValueError) as exc:self.messagebox.showerror("Template could not be saved",str(exc));return
        paths_by_platform={name:{choice:entry.get().strip() for choice,entry in entries.items()} for name,entries in self.template_entries.items()}
        templates=template_paths(platform,families,paths_by_platform)
        required_template="combined" if len(families)>1 else families[0]
        if make_ckl and not templates[required_template]:
            self.messagebox.showerror("CKL template required", "Choose the blank CKL template matching the selected STIG type."); return
        mode = self.mode.get()
        if mode == 'Live SSH' and (not self.user.get().strip() or not self.password.get()):
            self.messagebox.showerror('SSH credentials required', 'Enter the SSH username and password for a live audit.')
            return
        raw_output = self.output_dir.get().strip()
        if not raw_output:
            self.messagebox.showerror('Output folder required', 'Choose a folder for protected audit reports.')
            return
        try:
            output_dir = Path(raw_output).expanduser().resolve()
            output_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, ValueError) as exc:
            self.messagebox.showerror('Output folder unavailable', f'Could not create the output folder ({type(exc).__name__}).')
            return
        self.last_results,self.last_targets,self.last_families,self.last_run_id=[],[],[],''
        self.last_report_paths,self.last_output_dir=[],output_dir
        self.preview_summary()
        self.cancel_event.clear()
        self.status.configure(text=f'Running {len(addresses)} device(s)…')
        self.run_state_label.configure(text='RUNNING', text_color=self.colors['amber'])
        self.run_counts_label.configure(text=f'0 protected files  ·  0 failed devices  ·  {len(addresses)} selected')
        self.run_folder_label.configure(text=f'Output folder: {output_dir}')
        self.open_folder_button.configure(state='normal')
        self.view_latest_button.configure(state='disabled')
        targets = [DeviceTargetRecord(ip=x) for x in addresses]
        if mode == 'Live SSH':
            creds = self._take_ssh_credentials()
        else:
            self.password.delete(0, 'end')
            self.secret.delete(0, 'end')
            creds = None
        self.thread = threading.Thread(
            target=self._run,
            args=(targets,checks,profile,creds,families,mode,templates,make_txt,make_ckl,output_dir,bool(self.verify_host_keys.get())),
            daemon=True,
        )
        self.thread.start()
        self.root.after(150,self.poll)
    def _run(self,targets,checks,profile,creds,families,mode,templates,make_txt,make_ckl,output_dir,verify_host_key=True):
        written = []
        run_id = str(uuid.uuid4())
        stage = 'starting audit'
        result = None
        addresses = [target.ip for target in targets]
        try:
            stage = 'validating license'
            addresses=self.license_policy.validate((target.ip for target in targets),families,make_txt,make_ckl)
            targets=[DeviceTargetRecord(ip=ip) for ip in addresses]
            service=AuditService(); kwargs=dict(run_id=run_id,targets=targets,checks=checks,profile_provider=lambda _:profile,event_queue=self.events,cancel_event=self.cancel_event)
            stage = 'collecting and evaluating devices'
            result=service.run_offline(output_loader=sample_outputs,**kwargs) if mode=="Sample outputs" else service.run_live(credentials=creds,verify_host_key=verify_host_key,**kwargs)
            # Export is a separate licensed operation; expiry or replacement may have occurred while collecting.
            stage = 'validating license for export'
            self.license_policy.validate(addresses,families,make_txt,make_ckl)
            stage = 'saving protected reports'
            if result.assets: output_dir.mkdir(parents=True,exist_ok=True)
            if make_txt:
                for ip, asset in result.assets.items():
                    device_results=[r for r in result.results if r.ip == ip]
                    destination=output_dir/f"{report_stem(asset, ip, families)}_{run_id[:8]}.txt"
                    written.append(str(self.artifacts.save(destination,build_text_report(device_results).encode('utf-8'))))
            if make_ckl:
                for ip,asset in result.assets.items():
                    if len(families)>1:
                        dest=output_dir/f"{report_stem(asset, ip, families)}_{run_id[:8]}.ckl";content=render_completed_ckl(templates["combined"],[r for r in result.results if r.ip==ip],asset);written.append(str(self.artifacts.save(dest,content)));continue
                    for family in families:
                        template=templates[family]
                        subset=family_results([r for r in result.results if r.ip==ip],family); dest=output_dir/f"{report_stem(asset, ip, [family])}_{run_id[:8]}.ckl";content=render_completed_ckl(template,subset,asset);written.append(str(self.artifacts.save(dest,content)))
            failed=[outcome for outcome in result.summary.outcomes if not outcome.successful]
            if not written:
                state="cancelled" if result.summary.cancelled_count and not result.summary.failure_count else "failed"
                message=f"Audit {state}: no reports were created in {output_dir.resolve()}."
            elif failed:
                message=f"Partial audit: {len(written)} encrypted file(s) written to {output_dir.resolve()}."
            else:
                message=f"Completed. {len(written)} encrypted file(s) written to {output_dir.resolve()}."
            if written: message+="\n"+"\n".join(written)
            if failed: message+="\nDevice outcomes:\n"+"\n".join(_failed_outcome_text(outcome) for outcome in failed)
            run_state = 'completed' if written and not failed else ('partial' if written else state)
            self.events.put(SimpleNamespace(
                message=message, run_state=run_state, report_paths=list(written),
                output_dir=output_dir.resolve(), device_count=len(addresses),
                failed_count=result.summary.failure_count,
                cancelled_count=result.summary.cancelled_count,
                summary_results=list(result.results), summary_targets=list(addresses),
                summary_families=list(families), summary_run_id=run_id,
            ))
        except Exception as exc:
            logging.getLogger(__name__).exception('Basic audit failed during %s', stage)
            state = 'partial' if written else 'failed'
            message = f'Audit {state} during {stage} ({type(exc).__name__}). '
            if isinstance(exc, LicensePolicyError):
                limit = getattr(self.license_policy, 'device_limit', None)
                if isinstance(limit, int):
                    message += f'This license allows {limit} device(s) per audit. '
                message += 'Review the License tab and selected devices. '
            message += f'{len(written)} encrypted file(s) saved in {output_dir}.'
            if written: message += '\n' + '\n'.join(written)
            summary = getattr(result, 'summary', None)
            self.events.put(SimpleNamespace(
                message=message, run_state=state, report_paths=list(written),
                output_dir=output_dir, device_count=len(addresses),
                failed_count=getattr(summary, 'failure_count', len(addresses)),
                cancelled_count=getattr(summary, 'cancelled_count', 0),
            ))

    def _apply_run_completion(self, event):
        self.last_report_paths = list(event.report_paths)
        self.last_output_dir = Path(event.output_dir)
        state = event.run_state.upper()
        color = self.colors['teal'] if state == 'COMPLETED' else (
            self.colors['amber'] if state in {'PARTIAL', 'CANCELLED'} else self.colors['red']
        )
        self.run_state_label.configure(text=state, text_color=color)
        self.run_counts_label.configure(
            text=f'{len(event.report_paths)} protected file(s)  ·  {event.failed_count} failed device(s)'
                 + (f'  ·  {event.cancelled_count} cancelled' if event.cancelled_count else '')
        )
        self.run_folder_label.configure(text=f'Output folder: {event.output_dir}')
        self.open_folder_button.configure(state='normal' if self.last_output_dir.is_dir() else 'disabled')
        self.view_latest_button.configure(state='normal' if event.report_paths else 'disabled')

    def poll(self):
        try:
            while True:
                e=self.events.get_nowait()
                message = _scan_event_text(e) if hasattr(e, 'event_type') else e.message
                if message:
                    self.status.configure(text=message.splitlines()[0])
                    self.results_box.insert("end",message+"\n")
                if hasattr(e, 'run_state') and hasattr(self, 'run_state_label'):
                    self._apply_run_completion(e)
                    if e.run_state == 'failed':
                        self.messagebox.showerror('Audit failed', e.message)
                    elif e.run_state == 'partial':
                        self.messagebox.showwarning('Audit partially completed', e.message)
                if hasattr(e,'summary_results'):
                    self.last_results=e.summary_results;self.last_targets=e.summary_targets;self.last_families=e.summary_families;self.last_run_id=e.summary_run_id
                    self.summary_device.configure(values=['All devices']+sorted(set(e.summary_targets)));self.summary_device.set('All devices')
                    self.summary_family.configure(values=['All families']+sorted({r.stig_family for r in e.summary_results}));self.summary_family.set('All families')
                    self.preview_summary()
        except queue.Empty:pass
        if (self.thread and self.thread.is_alive()) or not self.events.empty():self.root.after(150,self.poll)
    
def run_basic_gui():
    import customtkinter as ctk
    from tkinter import messagebox, simpledialog
    root=ctk.CTk();root.withdraw()
    vault_path=default_vault_path()
    while True:
        creating=not vault_path.exists()
        prompt='Create an audit-data passphrase' if creating else 'Enter the audit-data passphrase'
        passphrase=simpledialog.askstring('Unlock Basic audit data',prompt,show='•',parent=root)
        if passphrase is None:root.destroy();return
        if creating:
            confirmation=simpledialog.askstring('Confirm audit-data passphrase','Enter the passphrase again',show='•',parent=root)
            if confirmation is None:root.destroy();return
            if passphrase!=confirmation:
                messagebox.showerror('Passphrases do not match','Try again.',parent=root);continue
        try:vault=AtRestVault.open(vault_path,passphrase,create=creating)
        except VaultUnlockError as exc:
            messagebox.showerror('Could not unlock audit data',str(exc),parent=root);continue
        except Exception as exc:
            logging.getLogger(__name__).exception('Basic vault failed unexpectedly during startup')
            messagebox.showerror('Could not open audit data',f'The vault could not be opened ({type(exc).__name__}). Check the application log for details.',parent=root)
            root.destroy()
            return
        finally:passphrase=''
        break
    try:
        root.deiconify()
        BasicApp(root,vault)
        root.after(0,root.deiconify)
    except Exception as exc:
        logging.getLogger(__name__).exception('Basic main window failed to initialize after vault unlock')
        messagebox.showerror('Basic could not start',f'The main window failed to open ({type(exc).__name__}). Check the application log for details.',parent=root)
        root.destroy()
        return
    root.mainloop()

__all__=["BasicApp","parse_device_text","parse_device_file","sample_outputs","run_basic_gui"]
