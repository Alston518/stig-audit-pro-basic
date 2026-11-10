"""Operator approval and management of trusted SSH public keys in Basic."""

from __future__ import annotations

import getpass
import logging
import threading
from dataclasses import dataclass, field
from tkinter import END, EXTENDED, Listbox, StringVar, messagebox, simpledialog, ttk

from stig_audit_pro.core.ssh_runner import DeviceTarget
from stig_audit_pro.infrastructure.ssh.host_keys import HostKeyTrustStore
from stig_audit_pro.infrastructure.ssh.netmiko_runner import DiscoveredHostKey
from stig_audit_pro.infrastructure.ssh.host_key_batch import HostKeyBatchPlan


TOFU_BATCH_NOTE = "First use acceptance; not independently verified."


@dataclass(slots=True)
class HostKeyRequest:
    target: DeviceTarget
    key: DiscoveredHostKey
    cancellation: threading.Event
    done: threading.Event = field(default_factory=threading.Event)
    approval: tuple[str, str] | None = None


@dataclass(slots=True)
class HostKeyBatchRequest:
    plan: HostKeyBatchPlan
    cancellation: threading.Event
    done: threading.Event = field(default_factory=threading.Event)
    approval_note: str | None = None


class ReviewHostKeyBatchDialog(simpledialog.Dialog):
    """Show every discovered first-use fingerprint before one explicit approval."""

    def __init__(self, parent, request: HostKeyBatchRequest) -> None:
        self.request = request
        super().__init__(parent, "Review SSH host keys")

    def body(self, frame):
        plan = self.request.plan
        ttk.Label(
            frame,
            text=f"Review {len(plan.unknown)} new SSH host key(s) before trusting them.",
        ).pack(anchor="w")
        ttk.Label(
            frame,
            text="Approving saves these first-use keys without independent verification. "
                 "Changed saved keys are blocked and cannot be approved here.",
            wraplength=780,
        ).pack(anchor="w", pady=(4, 8))
        rows = ttk.Frame(frame)
        rows.pack(fill="both", expand=True)
        columns = ("device", "status", "algorithm", "fingerprint")
        tree = ttk.Treeview(rows, columns=columns, show="headings", height=16)
        for name, width in (("device", 150), ("status", 125), ("algorithm", 115), ("fingerprint", 390)):
            tree.heading(name, text=name.title())
            tree.column(name, width=width, minwidth=80, stretch=name == "fingerprint")
        scroll = ttk.Scrollbar(rows, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        for entry in plan.unknown:
            tree.insert("", "end", values=(entry.target.ip, "NEW", entry.algorithm, entry.fingerprint))
        for entry in plan.changed:
            tree.insert("", "end", values=(entry.target.ip, "CHANGED — BLOCKED", entry.algorithm, entry.fingerprint))
        if plan.failed:
            ttk.Label(
                frame,
                text=f"{len(plan.failed)} device(s) could not be reached for key discovery. "
                     "They are not included in this approval and will be checked during the scan.",
                wraplength=780,
            ).pack(anchor="w", pady=(8, 0))
        ttk.Label(frame, text="Verification source (optional; leave blank for first-use acceptance):").pack(anchor="w", pady=(10, 0))
        self.note = ttk.Entry(frame, width=85)
        self.note.pack(fill="x", pady=(2, 4))
        return tree

    def buttonbox(self):
        frame = ttk.Frame(self)
        ttk.Button(frame, text="Trust all listed NEW keys", command=self.ok).pack(side="left", padx=4)
        ttk.Button(frame, text="Cancel scan", command=self.cancel).pack(side="left", padx=4)
        self.bind("<Escape>", self.cancel)
        frame.pack(pady=(0, 8))

    def validate(self):
        return messagebox.askyesno(
            "Trust new SSH host keys?",
            f"Save the {len(self.request.plan.unknown)} NEW host key(s) shown in the review list? "
            "If you entered no source, their identities have not been independently verified. "
            "Changed saved keys will remain blocked.",
            parent=self,
            default="no",
        )

    def apply(self):
        self.result = self.note.get().strip() or TOFU_BATCH_NOTE


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
            text="This switch has no saved SSH key. Trust and Save remembers this key "
                 "and continues the audit. On a first connection, compare the fingerprint "
                 "with a trusted source if you need to confirm the switch's identity.",
            wraplength=450,
        ).pack(anchor="w")
        return fingerprint

    def buttonbox(self):
        frame = ttk.Frame(self)
        ttk.Button(frame, text="Trust and Save", command=self.ok).pack(side="left", padx=4)
        ttk.Button(frame, text="Cancel", command=self.cancel).pack(side="left", padx=4)
        self.bind("<Escape>", self.cancel)
        frame.pack(pady=(0, 8))

    def apply(self):
        self.result = ("Operator accepted the SSH host key on first use.", getpass.getuser())


class ManageHostKeysDialog(simpledialog.Dialog):
    def __init__(self, parent, store: HostKeyTrustStore) -> None:
        self.store = store
        self.hosts = store.list_hosts()
        super().__init__(parent, "Manage SSH host keys")

    def body(self, frame):
        ttk.Label(frame, text="Select one or more switches to view or remove their trusted keys.").pack(anchor="w")
        rows = ttk.Frame(frame)
        rows.pack(fill="both", expand=True, pady=6)
        self.listbox = Listbox(rows, width=62, height=9, selectmode=EXTENDED, exportselection=False)
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
        ttk.Button(frame, text="Select all", command=self._select_all).pack(side="left", padx=4)
        self.remove_button = ttk.Button(frame, text="Remove selected keys", command=self._remove, state="disabled")
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
        if len(selection) > 1:
            self.detail.set(f"{len(selection)} saved host entries selected.")
        elif selection:
            self.detail.set("\n".join(self.hosts[self.listbox.get(selection[0])]))

    def _select_all(self):
        if self.hosts:
            self.listbox.selection_set(0, END)
            self._select()

    def _remove(self):
        selection = self.listbox.curselection()
        if not selection:
            return
        hosts = tuple(self.listbox.get(index) for index in selection)
        if not messagebox.askyesno(
            "Remove trusted host keys?",
            f"Remove {len(hosts)} saved SSH host key entr{'y' if len(hosts) == 1 else 'ies'}? "
            "The next verified connection to each switch will require enrollment again.",
            parent=self, default="no",
        ):
            return
        try:
            removed = self.store.remove_many(
                hosts, operator=getpass.getuser(),
                expected={host: self.hosts[host] for host in hosts},
            )
            self.hosts = self.store.list_hosts()
        except (OSError, ValueError):
            messagebox.showerror(
                "Host keys could not be removed",
                "No keys were removed. The trust store may be busy or an entry may have changed. Close this window and try again.",
                parent=self,
            )
            return
        logging.getLogger("stig_audit_pro.activity").warning(
            "HOST_KEYS_BULK_REMOVED operator=%s count=%s", getpass.getuser(), len(removed),
        )
        self._populate()
        self._select()
