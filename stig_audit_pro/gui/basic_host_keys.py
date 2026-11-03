"""Operator approval and management of trusted SSH public keys in Basic."""

from __future__ import annotations

import getpass
import threading
from dataclasses import dataclass, field
from tkinter import END, Listbox, StringVar, messagebox, simpledialog, ttk

from stig_audit_pro.core.ssh_runner import DeviceTarget
from stig_audit_pro.infrastructure.ssh.host_keys import HostKeyTrustStore
from stig_audit_pro.infrastructure.ssh.netmiko_runner import DiscoveredHostKey


@dataclass(slots=True)
class HostKeyRequest:
    target: DeviceTarget
    key: DiscoveredHostKey
    cancellation: threading.Event
    done: threading.Event = field(default_factory=threading.Event)
    approval: tuple[str, str] | None = None


class TrustHostKeyDialog(simpledialog.Dialog):
    def __init__(self, parent, request: HostKeyRequest) -> None:
        self.request = request
        super().__init__(parent, "Trust SSH host key?")

    def body(self, frame):
        request = self.request
        ttk.Label(frame, text=f"{request.target.ip} (port {request.target.port}) · {request.key.algorithm}").pack(anchor="w")
        fingerprint = ttk.Entry(frame, width=62)
        fingerprint.insert(0, request.key.fingerprint)
        fingerprint.configure(state="readonly")
        fingerprint.pack(fill="x", pady=(4, 10))
        ttk.Label(
            frame,
            text="Enter the SHA256 fingerprint from an independently trusted source. "
                 "If you cannot verify it, cancel to skip this switch.",
            wraplength=450,
        ).pack(anchor="w")
        self.expected = ttk.Entry(frame, width=62)
        self.expected.pack(fill="x", pady=(4, 8))
        ttk.Label(frame, text="Verification source (for example, approved key inventory)").pack(anchor="w")
        self.source = ttk.Entry(frame, width=62)
        self.source.pack(fill="x", pady=(4, 0))
        return self.expected

    def buttonbox(self):
        frame = ttk.Frame(self)
        ttk.Button(frame, text="Trust and Save", command=self.ok).pack(side="left", padx=4)
        ttk.Button(frame, text="Cancel", command=self.cancel).pack(side="left", padx=4)
        self.bind("<Escape>", self.cancel)
        frame.pack(pady=(0, 8))

    def validate(self):
        if self.expected.get().strip() != self.request.key.fingerprint:
            messagebox.showerror("Fingerprint does not match", "Enter the matching trusted fingerprint or cancel.", parent=self)
            return False
        if not self.source.get().strip():
            messagebox.showerror("Verification source required", "Enter where you verified the fingerprint.", parent=self)
            return False
        return True

    def apply(self):
        self.result = (self.source.get().strip(), getpass.getuser())


class ManageHostKeysDialog(simpledialog.Dialog):
    def __init__(self, parent, store: HostKeyTrustStore) -> None:
        self.store = store
        self.hosts = store.list_hosts()
        super().__init__(parent, "Manage SSH host keys")

    def body(self, frame):
        ttk.Label(frame, text="Select a saved switch to view or remove its trusted keys.").pack(anchor="w")
        rows = ttk.Frame(frame)
        rows.pack(fill="both", expand=True, pady=6)
        self.listbox = Listbox(rows, width=62, height=9, exportselection=False)
        scroll = ttk.Scrollbar(rows, orient="vertical", command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=scroll.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.detail = StringVar(master=self, value="Select a host to see its fingerprints.")
        ttk.Label(frame, textvariable=self.detail, wraplength=460).pack(anchor="w")
        self.listbox.bind("<<ListboxSelect>>", self._select)
        self._populate()
        return self.listbox

    def buttonbox(self):
        frame = ttk.Frame(self)
        self.remove_button = ttk.Button(frame, text="Remove selected host", command=self._remove, state="disabled")
        self.remove_button.pack(side="left", padx=4)
        ttk.Button(frame, text="Close", command=self.cancel).pack(side="left", padx=4)
        self.bind("<Escape>", self.cancel)
        frame.pack(pady=(0, 8))

    def _populate(self):
        self.listbox.delete(0, END)
        for host in sorted(self.hosts):
            self.listbox.insert(END, host)
        self.detail.set("Select a host to see its fingerprints." if self.hosts else "No trusted SSH host keys are stored.")

    def _select(self, _event=None):
        selection = self.listbox.curselection()
        self.remove_button.configure(state="normal" if selection else "disabled")
        if selection:
            self.detail.set("\n".join(self.hosts[self.listbox.get(selection[0])]))

    def _remove(self):
        selection = self.listbox.curselection()
        if not selection:
            return
        host = self.listbox.get(selection[0])
        if not messagebox.askyesno(
            "Remove trusted host keys?",
            f"Remove the saved SSH keys for {host}? The next verified connection will require enrollment.",
            parent=self, default="no",
        ):
            return
        try:
            self.store.remove(host, operator=getpass.getuser(), expected=self.hosts[host])
            self.hosts = self.store.list_hosts()
        except (OSError, ValueError):
            messagebox.showerror(
                "Host key could not be removed",
                "The trust store may be busy or the entry may have changed. Close this window and try again.",
                parent=self,
            )
            return
        self._populate()
        self._select()
