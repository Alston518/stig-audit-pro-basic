"""Operator-first, read-only STIG audit workflow for the Basic edition."""
from __future__ import annotations
import csv, ipaddress, json, queue, re, threading, uuid, shutil, sys
from datetime import datetime
from pathlib import Path
from stig_audit_pro.application.audit_service import AuditService
from stig_audit_pro.core.ssh_runner import DeviceCredentials
from stig_audit_pro.core.yaml_loader import ConfigValidationError, load_check_library, load_profile
from stig_audit_pro.reports.audit_report import write_text_report
from stig_audit_pro.reports.basic_summary import Filter, STATUSES, CATS, cat, summarize, export_csv, export_html, export_pdf
from stig_audit_pro.stig.ckl_writer import write_completed_ckl
from stig_audit_pro.storage.device_groups import DeviceTargetRecord
from stig_audit_pro.licensing import LicenseImportError, LicensePolicyError
from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy, normalize_basic_targets

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
        idx = next((headers.index(x) for x in ("ip","address","host","hostname") if x in headers), 0)
        return parse_device_text("\n".join(r[idx] for r in rows[1:] if len(r) > idx))
    return parse_device_text(p.read_text(encoding="utf-8-sig"))

def sample_outputs(target: DeviceTargetRecord) -> dict[str, str]:
    root = Path(__file__).resolve().parents[1] / "tests" / "sample_outputs"
    folder = root / ("noncompliant" if target.ip.split(".")[-1:] == ["26"] else "compliant")
    return {c: (folder / f).read_text(encoding="utf-8", errors="replace") for c, f in COMMAND_FILES.items() if (folder / f).exists()}

def report_stem(asset, scan_ip: str, families: list[str], when: datetime | None = None) -> str:
    """Build the operator-facing filename stem requested for Basic reports."""
    address = asset.management_ip or scan_ip
    try:
        octet = str(ipaddress.ip_address(address).version == 4 and address.split(".")[-1] or scan_ip.split(".")[-1])
    except ValueError:
        octet = scan_ip.split(".")[-1] if "." in scan_ip else "device"
    platform = "IOSXE" if all(f.startswith("iosxe_") for f in families) else "IOS"
    label = "_".join(f.rsplit("_", 1)[-1].upper() for f in families)
    date_text = (when or datetime.now()).strftime("%d%b%Y").upper()
    return f"{octet}_{platform}_{label}_{date_text}"

class BasicApp:
    def __init__(self, root):
        import customtkinter as ctk
        from tkinter import filedialog, messagebox
        from platformdirs import user_documents_dir
        self.root, self.ctk, self.filedialog, self.messagebox = root, ctk, filedialog, messagebox
        self.events, self.cancel_event, self.thread = queue.Queue(), threading.Event(), None
        self.last_results,self.last_targets,self.last_families,self.last_run_id=[],[],[],''
        self.license_policy = BasicLicensePolicy()
        self.selected_addresses = ['192.0.2.10']
        self.selection_dialog = None
        self.project_root = Path(user_documents_dir()) / "STIG Audit Pro Basic"
        self.workspace = self.project_root / "Workspace"
        self.package_templates=(Path(sys.executable).resolve().parent.parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parents[2])/'Checklist Templates'
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
        self._build()
        self.refresh_license_status()
        self._license_timer = self.root.after(30000, self.check_license_timer)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build(self):
        ctk = self.ctk; self.root.title("STIG Audit Pro Basic — Read-Only Switch Audit"); self.root.geometry("980x720")
        ctk.CTkLabel(self.root, text="STIG Audit Pro Basic", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=24, pady=(16,0))
        ctk.CTkLabel(self.root, text="Run YAML checks and produce CKL or text output. Network commands are read-only.").pack(anchor="w", padx=24)
        tabs=ctk.CTkTabview(self.root); tabs.pack(fill="both", expand=True, padx=18, pady=12)
        audit_tab=tabs.add("Audit"); audit=ctk.CTkScrollableFrame(audit_tab); audit.pack(fill="both",expand=True)
        result=tabs.add("Results"); summary=tabs.add("Summary"); license_tab=tabs.add("License"); help_=tabs.add("Help")
        self._build_summary(summary)
        from stig_audit_pro.gui.basic_license_ui import BasicLicensePanel
        self.license_panel=BasicLicensePanel(license_tab,self.import_license_file,self.refresh_license_status)
        self.license_panel.pack(fill="both",expand=True)
        self.results_box=ctk.CTkTextbox(result); self.results_box.pack(fill="both", expand=True, padx=12, pady=12)
        ctk.CTkLabel(help_, justify="left", text="Paste device IPs or import CSV/TXT, then click Select devices.\nFree Basic runs one selected device per audit; your full list stays in the box.\nImport a signed license on the License tab for its batch limit and enabled features.\nChoose IOS XE or IOS, a STIG family, and a profile.\nSample outputs are available for IOS XE only; Live SSH uses approved read-only commands.\nChoose a blank CKL template matching the selected platform and STIG family.\nTemplates default to this package's Checklist Templates folder. Browse saves the chosen path.\nAfter a run, use Summary to export combined PDF, HTML, or CSV for that run.\nCredentials are held in memory only and are never saved.\n\nEditable checks and profiles are beside this application in the data folder.\nIOS starter checks require review against the approved benchmark and real IOS output.").pack(anchor="nw", padx=18, pady=18)
        self.devices=ctk.CTkTextbox(audit,height=100); self.devices.pack(fill="x", padx=12, pady=8); self.devices.insert("1.0","192.0.2.10\n")
        self.devices.bind('<KeyRelease>', lambda _: self.sync_selected_devices())
        selection_row=ctk.CTkFrame(audit);selection_row.pack(fill='x',padx=12,pady=4)
        ctk.CTkButton(selection_row,text='Select devices',command=self.select_devices).pack(side='left',padx=4,pady=4)
        self.selection_label=ctk.CTkLabel(selection_row,text='',justify='left',anchor='w',wraplength=660)
        self.selection_label.pack(side='left',fill='x',expand=True,padx=8)
        row=ctk.CTkFrame(audit); row.pack(fill="x", padx=12, pady=4); self.platform=ctk.CTkOptionMenu(row,values=["IOS XE","IOS"],command=self.on_platform_change); self.platform.pack(side="left",padx=4); self.platform.set("IOS XE"); self.family=ctk.CTkOptionMenu(row,values=["L2","NDM","L2 + NDM"],command=lambda _: self.update_paths()); self.family.pack(side="left",padx=4); self.mode=ctk.CTkOptionMenu(row,values=["Sample outputs","Live SSH"]); self.mode.pack(side="left",padx=4); self.profile=ctk.CTkOptionMenu(row,values=self._profiles(),command=lambda _: self.update_paths()); self.profile.pack(side="left",padx=4); self.profile.set(default_profile_name("IOS XE")); ctk.CTkButton(row,text="Import CSV/TXT",command=self.import_devices).pack(side="left",padx=4)
        self.path_label=ctk.CTkLabel(audit,justify="left",anchor="w",text=""); self.path_label.pack(fill="x", padx=16, pady=(0,4)); self.update_paths()
        cred=ctk.CTkFrame(audit); cred.pack(fill="x",padx=12,pady=4); self.user=ctk.CTkEntry(cred,placeholder_text="SSH username"); self.user.pack(side="left",fill="x",expand=True,padx=4); self.password=ctk.CTkEntry(cred,placeholder_text="SSH password",show="•"); self.password.pack(side="left",fill="x",expand=True,padx=4); self.secret=ctk.CTkEntry(cred,placeholder_text="Enable secret (optional)",show="•"); self.secret.pack(side="left",fill="x",expand=True,padx=4)
        self.template_tabs=ctk.CTkTabview(audit,height=170); self.template_tabs.pack(fill="x",padx=12,pady=4)
        self.template_entries={}
        for platform_name in ("IOS XE", "IOS"):
            template_tab=self.template_tabs.add(platform_name)
            self.template_entries[platform_name]={}
            for choice in ("L2", "NDM", "L2 + NDM"):
                template_row=ctk.CTkFrame(template_tab); template_row.pack(fill="x",padx=4,pady=2)
                ctk.CTkLabel(template_row,text=choice,width=85).pack(side="left",padx=4)
                entry=ctk.CTkEntry(template_row,placeholder_text=f"{platform_name} {choice} blank CKL template")
                entry.pack(side="left",fill="x",expand=True,padx=4)
                ctk.CTkButton(template_row,text="Browse",width=85,command=lambda selected=entry,p=platform_name,c=choice:self.browse_template(selected,p,c)).pack(side="left",padx=4)
                self.template_entries[platform_name][choice]=entry
        for platform_name, choices in load_template_paths(self.package_templates,self.workspace / "CKL Templates",self.template_settings).items():
            for choice, path in choices.items():
                if path: self.template_entries[platform_name][choice].insert(0, path)
        self.template_tabs.set("IOS XE")
        out=ctk.CTkFrame(audit); out.pack(fill="x",padx=12,pady=4); self.output_dir=ctk.CTkEntry(out); self.output_dir.pack(side="left",fill="x",expand=True,padx=4); self.output_dir.insert(0,str(self.workspace/"Completed CKLs")); ctk.CTkButton(out,text="Choose output folder",command=self.browse_output).pack(side="left",padx=4)
        formats=ctk.CTkFrame(audit); formats.pack(fill="x",padx=12,pady=4); ctk.CTkLabel(formats,text="Create:").pack(side="left",padx=4); self.txt_var=ctk.BooleanVar(value=True); self.ckl_var=ctk.BooleanVar(value=True); ctk.CTkCheckBox(formats,text="TXT report",variable=self.txt_var).pack(side="left",padx=8); ctk.CTkCheckBox(formats,text="CKL checklist",variable=self.ckl_var).pack(side="left",padx=8)
        actions=ctk.CTkFrame(audit); actions.pack(fill="x",padx=12,pady=8); ctk.CTkButton(actions,text="Start Audit",command=self.start).pack(side="left",padx=4); ctk.CTkButton(actions,text="Cancel",command=lambda:self.cancel_event.set()).pack(side="left",padx=4); self.status=ctk.CTkLabel(audit,text="Ready"); self.status.pack(anchor="w",padx=16)

    def _build_summary(self,tab):
        ctk=self.ctk
        ctk.CTkLabel(tab,text='Combined summary for the current audit run',font=ctk.CTkFont(size=18,weight='bold')).pack(anchor='w',padx=12,pady=(12,2))
        ctk.CTkLabel(tab,text='Choose filters, click Preview, then export PDF, HTML, or CSV. Per-device TXT and CKL reports stay available.',wraplength=820).pack(anchor='w',padx=12)
        row=ctk.CTkFrame(tab);row.pack(fill='x',padx=12,pady=8)
        self.summary_status=ctk.CTkOptionMenu(row,values=['All results','Open only','Not a Finding only','Needs review','Errors only','Skipped only','Not Applicable only','Not Reviewed only']);self.summary_status.pack(side='left',padx=3);self.summary_status.set('All results')
        self.summary_cat=ctk.CTkOptionMenu(row,values=['All CATs','CAT I','CAT II','CAT III','Other']);self.summary_cat.pack(side='left',padx=3);self.summary_cat.set('All CATs')
        self.summary_device=ctk.CTkOptionMenu(row,values=['All devices']);self.summary_device.pack(side='left',padx=3);self.summary_device.set('All devices')
        self.summary_family=ctk.CTkOptionMenu(row,values=['All families']);self.summary_family.pack(side='left',padx=3);self.summary_family.set('All families')
        row=ctk.CTkFrame(tab);row.pack(fill='x',padx=12,pady=4)
        self.summary_pdf=ctk.BooleanVar(value=True);self.summary_html=ctk.BooleanVar(value=True);self.summary_csv=ctk.BooleanVar(value=True)
        for label,var in [('PDF with charts',self.summary_pdf),('HTML with charts',self.summary_html),('CSV details',self.summary_csv)]:ctk.CTkCheckBox(row,text=label,variable=var).pack(side='left',padx=8,pady=5)
        ctk.CTkButton(row,text='Export summary',command=self.export_summary).pack(side='right',padx=5)
        ctk.CTkButton(row,text='Preview',command=self.preview_summary).pack(side='right',padx=5)
        self.summary_box=ctk.CTkTextbox(tab);self.summary_box.pack(fill='both',expand=True,padx=12,pady=8);self.summary_box.insert('1.0','Run an audit first. The summary covers only devices in that run.')

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
        choices=[('pdf',self.summary_pdf.get(),export_pdf),('html',self.summary_html.get(),export_html),('csv',self.summary_csv.get(),export_csv)]
        if not any(enabled for _,enabled,_ in choices):self.messagebox.showerror('Choose format','Select PDF, HTML, or CSV.');return []
        try:
            self.license_policy.validate(self.last_targets,self.last_families,True,False)
            report=summarize(self.last_results,self._summary_filter(),self.last_targets)
            folder=Path(self.output_dir.get()).expanduser();folder.mkdir(parents=True,exist_ok=True)
            stem='OVERALL_SUMMARY_'+self.last_run_id[:8]+'_'+datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            paths=[writer(report,folder/f'{stem}.{ext}') for ext,enabled,writer in choices if enabled]
        except (LicensePolicyError,OSError,ValueError) as exc:self.messagebox.showerror('Summary not exported',str(exc));return []
        self.preview_summary();self.messagebox.showinfo('Summary exported','Created:\n'+'\n'.join(str(p) for p in paths));return paths

    def _profiles(self): return [p.stem for p in sorted((self.data_root/"profiles").glob("*.yaml"))] or ["base_iosxe_access"]
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
        if getattr(self,'_license_timer',None):self.root.after_cancel(self._license_timer)
        try:self.store_template_entries()
        except (OSError,ValueError):pass
        self.root.destroy()
    def browse_output(self):
        p=self.filedialog.askdirectory()
        if p: self.output_dir.delete(0,"end"); self.output_dir.insert(0,p)
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
        self.last_results,self.last_targets,self.last_families,self.last_run_id=[],[],[],'';self.preview_summary()
        self.cancel_event.clear();self.status.configure(text=f"Running {len(addresses)} device(s)…"); targets=[DeviceTargetRecord(ip=x) for x in addresses]; creds=DeviceCredentials(username=self.user.get(),password=self.password.get(),secret=self.secret.get() or None); mode=self.mode.get(); output_dir=Path(self.output_dir.get()).expanduser(); self.thread=threading.Thread(target=self._run,args=(targets,checks,profile,creds,families,mode,templates,make_txt,make_ckl,output_dir),daemon=True);self.thread.start();self.root.after(150,self.poll)
    def _run(self,targets,checks,profile,creds,families,mode,templates,make_txt,make_ckl,output_dir):
        try:
            addresses=self.license_policy.validate((target.ip for target in targets),families,make_txt,make_ckl)
            targets=[DeviceTargetRecord(ip=ip) for ip in addresses]
            service=AuditService();run_id=str(uuid.uuid4()); kwargs=dict(run_id=run_id,targets=targets,checks=checks,profile_provider=lambda _:profile,event_queue=self.events,cancel_event=self.cancel_event)
            result=service.run_offline(output_loader=sample_outputs,**kwargs) if mode=="Sample outputs" else service.run_live(credentials=creds,**kwargs)
            # Export is a separate licensed operation; expiry or replacement may have occurred while collecting.
            self.license_policy.validate(addresses,families,make_txt,make_ckl)
            written=[]; output_dir.mkdir(parents=True,exist_ok=True)
            if make_txt:
                for ip, asset in result.assets.items():
                    device_results=[r for r in result.results if r.ip == ip]
                    written.append(str(write_text_report(device_results, output_dir / f"{report_stem(asset, ip, families)}.txt")))
            if make_ckl:
                for ip,asset in result.assets.items():
                    if len(families)>1:
                        dest=output_dir/f"{report_stem(asset, ip, families)}.ckl";write_completed_ckl(templates["combined"],dest,[r for r in result.results if r.ip==ip],asset);written.append(str(dest));continue
                    for family in families:
                        template=templates[family]
                        subset=family_results([r for r in result.results if r.ip==ip],family); dest=output_dir/f"{report_stem(asset, ip, [family])}.ckl";write_completed_ckl(template,dest,subset,asset);written.append(str(dest))
            self.events.put(type("E",(),{"message":"Completed. Files written:\n"+"\n".join(written),"summary_results":list(result.results),"summary_targets":list(addresses),"summary_families":list(families),"summary_run_id":run_id})())
        except Exception as exc:self.events.put(type("E",(),{"message":f"Audit failed: {exc}"})())
    def poll(self):
        try:
            while True:
                e=self.events.get_nowait();self.status.configure(text=e.message);self.results_box.insert("end",e.message+"\n")
                if hasattr(e,'summary_results'):
                    self.last_results=e.summary_results;self.last_targets=e.summary_targets;self.last_families=e.summary_families;self.last_run_id=e.summary_run_id
                    self.summary_device.configure(values=['All devices']+sorted(set(e.summary_targets)));self.summary_device.set('All devices')
                    self.summary_family.configure(values=['All families']+sorted({r.stig_family for r in e.summary_results}));self.summary_family.set('All families')
                    self.preview_summary()
        except queue.Empty:pass
        if self.thread and self.thread.is_alive():self.root.after(150,self.poll)
    
def run_basic_gui():
    import customtkinter as ctk
    root=ctk.CTk();BasicApp(root);root.mainloop()

__all__=["BasicApp","parse_device_text","parse_device_file","sample_outputs","run_basic_gui"]
