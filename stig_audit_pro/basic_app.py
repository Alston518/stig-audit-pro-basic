"""Operator-first, read-only STIG audit workflow for the Basic edition."""
from __future__ import annotations
import csv, ipaddress, queue, re, threading, uuid, shutil, sys
from datetime import datetime
from pathlib import Path
from stig_audit_pro.application.audit_service import AuditService
from stig_audit_pro.core.ssh_runner import DeviceCredentials
from stig_audit_pro.core.yaml_loader import ConfigValidationError, load_check_library, load_profile
from stig_audit_pro.reports.audit_report import write_text_report
from stig_audit_pro.stig.ckl_writer import write_completed_ckl
from stig_audit_pro.storage.device_groups import DeviceTargetRecord

COMMAND_FILES = {
    "show running-config":"show_running_config.txt", "show vtp status":"show_vtp_status.txt",
    "show interfaces status":"show_interfaces_status.txt",
    "show interfaces switchport | include Negotiation of Trunking":"show_interfaces_switchport_negotiation.txt",
    "show interfaces trunk":"show_interfaces_trunk.txt", "show cdp neighbors detail":"show_cdp_neighbors_detail.txt",
    "show ip access-lists":"show_ip_access_lists.txt", "show ip dhcp snooping":"show_ip_dhcp_snooping.txt",
    "show ip arp inspection":"show_ip_arp_inspection.txt", "show snmp user":"show_snmp_user.txt",
    "show running-config | include ssh":"show_running_config_include_ssh.txt", "show version":"show_version.txt",
}

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
    label = "_".join("L2" if f == "iosxe_l2" else "NDM" for f in families)
    date_text = (when or datetime.now()).strftime("%d%b%Y").upper()
    return f"{octet}_IOSXE_{label}_{date_text}"

class BasicApp:
    def __init__(self, root):
        import customtkinter as ctk
        from tkinter import filedialog, messagebox
        from platformdirs import user_documents_dir
        self.root, self.ctk, self.filedialog, self.messagebox = root, ctk, filedialog, messagebox
        self.events, self.cancel_event, self.thread = queue.Queue(), threading.Event(), None
        self.project_root = Path(user_documents_dir()) / "STIG Audit Pro Basic"
        self.workspace = self.project_root / "Workspace"
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

    def _build(self):
        ctk = self.ctk; self.root.title("STIG Audit Pro Basic — Read-Only IOS-XE Audit"); self.root.geometry("980x720")
        ctk.CTkLabel(self.root, text="STIG Audit Pro Basic", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=24, pady=(16,0))
        ctk.CTkLabel(self.root, text="Run YAML checks and produce CKL or text output. Network commands are read-only.").pack(anchor="w", padx=24)
        tabs=ctk.CTkTabview(self.root); tabs.pack(fill="both", expand=True, padx=18, pady=12); audit=tabs.add("Audit"); result=tabs.add("Results"); help_=tabs.add("Help")
        self.results_box=ctk.CTkTextbox(result); self.results_box.pack(fill="both", expand=True, padx=12, pady=12)
        ctk.CTkLabel(help_, justify="left", text="Paste device IPs or import CSV/TXT. Choose an STIG family and profile.\nSample outputs lets you test without a switch; Live SSH uses approved read-only commands.\nSelect CKL templates to populate DISA checklists. Text reports are always written.\nCredentials are held in memory only and are never saved.\n\nEditable data is copied to your user data folder on first launch.").pack(anchor="nw", padx=18, pady=18)
        self.devices=ctk.CTkTextbox(audit,height=100); self.devices.pack(fill="x", padx=12, pady=8); self.devices.insert("1.0","192.0.2.10\n")
        row=ctk.CTkFrame(audit); row.pack(fill="x", padx=12, pady=4); self.family=ctk.CTkOptionMenu(row,values=["L2","NDM","L2 + NDM"],command=lambda _: self.update_paths()); self.family.pack(side="left",padx=4); self.mode=ctk.CTkOptionMenu(row,values=["Sample outputs","Live SSH"]); self.mode.pack(side="left",padx=4); self.profile=ctk.CTkOptionMenu(row,values=self._profiles(),command=lambda _: self.update_paths()); self.profile.pack(side="left",padx=4); ctk.CTkButton(row,text="Import CSV/TXT",command=self.import_devices).pack(side="left",padx=4)
        self.path_label=ctk.CTkLabel(audit,justify="left",anchor="w",text=""); self.path_label.pack(fill="x", padx=16, pady=(0,4)); self.update_paths()
        cred=ctk.CTkFrame(audit); cred.pack(fill="x",padx=12,pady=4); self.user=ctk.CTkEntry(cred,placeholder_text="SSH username"); self.user.pack(side="left",fill="x",expand=True,padx=4); self.password=ctk.CTkEntry(cred,placeholder_text="SSH password",show="•"); self.password.pack(side="left",fill="x",expand=True,padx=4); self.secret=ctk.CTkEntry(cred,placeholder_text="Enable secret (optional)",show="•"); self.secret.pack(side="left",fill="x",expand=True,padx=4)
        paths=ctk.CTkFrame(audit); paths.pack(fill="x",padx=12,pady=4)
        self.l2=ctk.CTkEntry(paths,placeholder_text="L2 blank CKL template"); self.l2.pack(fill="x",padx=4,pady=2); ctk.CTkButton(paths,text="Browse L2",width=100,command=lambda:self.browse(self.l2)).pack(anchor="e",padx=4)
        self.ndm=ctk.CTkEntry(paths,placeholder_text="NDM blank CKL template"); self.ndm.pack(fill="x",padx=4,pady=2); ctk.CTkButton(paths,text="Browse NDM",width=100,command=lambda:self.browse(self.ndm)).pack(anchor="e",padx=4)
        self.both=ctk.CTkEntry(paths,placeholder_text="L2 + NDM blank CKL template"); self.both.pack(fill="x",padx=4,pady=2); ctk.CTkButton(paths,text="Browse L2 + NDM",width=100,command=lambda:self.browse(self.both)).pack(anchor="e",padx=4)
        out=ctk.CTkFrame(audit); out.pack(fill="x",padx=12,pady=4); self.output_dir=ctk.CTkEntry(out); self.output_dir.pack(side="left",fill="x",expand=True,padx=4); self.output_dir.insert(0,str(self.workspace/"Completed CKLs")); ctk.CTkButton(out,text="Choose output folder",command=self.browse_output).pack(side="left",padx=4)
        formats=ctk.CTkFrame(audit); formats.pack(fill="x",padx=12,pady=4); ctk.CTkLabel(formats,text="Create:").pack(side="left",padx=4); self.txt_var=ctk.BooleanVar(value=True); self.ckl_var=ctk.BooleanVar(value=True); ctk.CTkCheckBox(formats,text="TXT report",variable=self.txt_var).pack(side="left",padx=8); ctk.CTkCheckBox(formats,text="CKL checklist",variable=self.ckl_var).pack(side="left",padx=8)
        actions=ctk.CTkFrame(audit); actions.pack(fill="x",padx=12,pady=8); ctk.CTkButton(actions,text="Start Audit",command=self.start).pack(side="left",padx=4); ctk.CTkButton(actions,text="Cancel",command=lambda:self.cancel_event.set()).pack(side="left",padx=4); self.status=ctk.CTkLabel(audit,text="Ready"); self.status.pack(anchor="w",padx=16)

    def _profiles(self): return [p.stem for p in sorted((self.data_root/"profiles").glob("*.yaml"))] or ["base_iosxe_access"]
    def update_paths(self):
        family_files={"L2":"iosxe_l2.yaml","NDM":"iosxe_ndm.yaml","L2 + NDM":"iosxe_l2.yaml + iosxe_ndm.yaml"}
        self.path_label.configure(text=f"Base check file(s): {self.data_root / 'checks' / family_files.get(self.family.get(),'iosxe_l2.yaml')}\nOptional site profile: {self.data_root / 'profiles' / (self.profile.get() + '.yaml')}\nEditable data folder: {self.data_root}")
    def browse(self,e):
        p=self.filedialog.askopenfilename(filetypes=[("CKL/XML","*.ckl *.xml"),("All files","*.*")]);
        if p: e.delete(0,"end"); e.insert(0,p)
    def browse_output(self):
        p=self.filedialog.askdirectory()
        if p: self.output_dir.delete(0,"end"); self.output_dir.insert(0,p)
    def import_devices(self):
        p=self.filedialog.askopenfilename(filetypes=[("Device list","*.csv *.txt"),("All files","*.*")]);
        if not p:return
        try:v,issues=parse_device_file(p)
        except Exception as exc:self.messagebox.showerror("Import failed",str(exc));return
        self.devices.delete("1.0","end");self.devices.insert("1.0","\n".join(v));self.messagebox.showwarning("Import review",f"{len(v)} valid devices.\n"+("\n".join(issues) if issues else "No problems found."))
    def start(self):
        if self.thread and self.thread.is_alive():return
        addresses,_=parse_device_text(self.devices.get("1.0","end"));
        if not addresses:self.messagebox.showerror("No devices","Add at least one valid address.");return
        families=["iosxe_l2","iosxe_ndm"] if self.family.get()=="L2 + NDM" else (["iosxe_l2"] if self.family.get()=="L2" else ["iosxe_ndm"])
        try:
            checks=[]
            for f in families:checks.extend(load_check_library(self.data_root/"checks"/f"{f}.yaml").checks)
            profile=load_profile(self.data_root/"profiles"/f"{self.profile.get()}.yaml",profiles_dir=self.data_root/"profiles")
        except (ConfigValidationError,OSError) as exc:self.messagebox.showerror("Configuration not ready",str(exc));return
        make_txt, make_ckl = bool(self.txt_var.get()), bool(self.ckl_var.get())
        if not make_txt and not make_ckl: self.messagebox.showerror("Choose an output", "Select TXT report, CKL checklist, or both."); return
        templates={"iosxe_l2":self.l2.get().strip(),"iosxe_ndm":self.ndm.get().strip(),"combined":self.both.get().strip()}
        if make_ckl and ((self.family.get()=="L2" and not templates["iosxe_l2"]) or (self.family.get()=="NDM" and not templates["iosxe_ndm"]) or (self.family.get()=="L2 + NDM" and not templates["combined"])):
            self.messagebox.showerror("CKL template required", "Choose the blank CKL template matching the selected STIG type."); return
        self.cancel_event.clear();self.status.configure(text=f"Running {len(addresses)} device(s)…"); targets=[DeviceTargetRecord(ip=x) for x in addresses]; creds=DeviceCredentials(username=self.user.get(),password=self.password.get(),secret=self.secret.get() or None); mode=self.mode.get(); output_dir=Path(self.output_dir.get()).expanduser(); self.thread=threading.Thread(target=self._run,args=(targets,checks,profile,creds,families,mode,templates,make_txt,make_ckl,output_dir),daemon=True);self.thread.start();self.root.after(150,self.poll)
    def _run(self,targets,checks,profile,creds,families,mode,templates,make_txt,make_ckl,output_dir):
        try:
            service=AuditService();run_id=str(uuid.uuid4()); kwargs=dict(run_id=run_id,targets=targets,checks=checks,profile_provider=lambda _:profile,event_queue=self.events,cancel_event=self.cancel_event)
            result=service.run_offline(output_loader=sample_outputs,**kwargs) if mode=="Sample outputs" else service.run_live(credentials=creds,**kwargs)
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
                        subset=[r for r in result.results if r.ip==ip and r.stig_family==family]; dest=output_dir/f"{report_stem(asset, ip, [family])}.ckl";write_completed_ckl(template,dest,subset,asset);written.append(str(dest))
            self.events.put(type("E",(),{"message":"Completed. Files written:\n"+"\n".join(written)})())
        except Exception as exc:self.events.put(type("E",(),{"message":f"Audit failed: {exc}"})())
    def poll(self):
        try:
            while True:
                e=self.events.get_nowait();self.status.configure(text=e.message);self.results_box.insert("end",e.message+"\n")
        except queue.Empty:pass
        if self.thread and self.thread.is_alive():self.root.after(150,self.poll)
    
def run_basic_gui():
    import customtkinter as ctk
    root=ctk.CTk();BasicApp(root);root.mainloop()

__all__=["BasicApp","parse_device_text","parse_device_file","sample_outputs","run_basic_gui"]
