"""Small license and device-selection panels for the Basic edition."""
import customtkinter as ctk
from stig_audit_pro.licensing.basic_policy import BASIC_FEATURE_LABELS


class BasicLicensePanel(ctk.CTkScrollableFrame):
    def __init__(self, master, import_command, refresh_command):
        super().__init__(master)
        self.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(self, text='Basic license', font=ctk.CTkFont(size=20, weight='bold')).grid(row=0, column=0, columnspan=2, sticky='w', padx=12, pady=12)
        self.values = {}
        for row, (key, label) in enumerate([
            ('status','Status'), ('customer','Customer'), ('license_id','License ID'),
            ('edition','License edition'), ('expires','Expires (UTC)'),
            ('limit','Devices per audit'), ('path','Installed license file'),
        ],1):
            ctk.CTkLabel(self,text=label,anchor='w').grid(row=row,column=0,sticky='nw',padx=12,pady=5)
            value=ctk.CTkLabel(self,text='',justify='left',anchor='w',wraplength=590)
            value.grid(row=row,column=1,sticky='ew',padx=12,pady=5)
            self.values[key]=value
        self.features=ctk.CTkLabel(self,text='',anchor='w',justify='left')
        self.features.grid(row=8,column=0,columnspan=2,sticky='w',padx=12,pady=12)
        ctk.CTkButton(self,text='Import / Replace License',command=import_command).grid(row=9,column=0,padx=12,pady=8)
        ctk.CTkButton(self,text='Refresh License',command=refresh_command).grid(row=9,column=1,sticky='w',padx=12,pady=8)
        self.message=ctk.CTkLabel(self,text='',wraplength=800,anchor='w',justify='left')
        self.message.grid(row=10,column=0,columnspan=2,sticky='w',padx=12,pady=12)

    def refresh(self, policy):
        info=policy.summary()
        status=info['status'] if info['valid'] else f"{info['status']} — Free Basic"
        values=dict(info,status=status,limit=str(info['device_limit']),
                    expires=info['expires'].strftime('%Y-%m-%d %H:%M:%S UTC') if info['expires'] else '—')
        for key,label in self.values.items(): label.configure(text=values.get(key) or '—')
        self.features.configure(text='\n'.join(f"{'Enabled' if info['features'][key] else 'Disabled'}: {label}" for key,label in BASIC_FEATURE_LABELS.items()))
        message=('This signed license is verified offline. The limit applies to selected devices per audit.' if info['valid'] else
                 'Free Basic: keep as many devices in your list as needed and select one device per audit. L2, NDM, TXT, and CKL remain available.')
        if info['errors']: message+='\n'+info['errors'][0]
        message+='\nExisting reports and checklist templates are kept. No internet activation is required.'
        self.message.configure(text=message)


class DeviceSelectionDialog(ctk.CTkToplevel):
    def __init__(self, master, addresses, selected, limit, on_apply):
        super().__init__(master)
        self.title('Select devices to audit'); self.geometry('600x460')
        self.transient(master)
        self.limit=limit; self.on_apply=on_apply
        ctk.CTkLabel(self,text=f'Select up to {limit} device(s) for this audit.',font=ctk.CTkFont(size=16,weight='bold')).pack(anchor='w',padx=16,pady=(14,4))
        ctk.CTkLabel(self,text='Your full device list stays unchanged.').pack(anchor='w',padx=16)
        frame=ctk.CTkScrollableFrame(self);frame.pack(fill='both',expand=True,padx=16,pady=10)
        self.variables={}
        for address in addresses:
            variable=ctk.BooleanVar(value=address in selected)
            self.variables[address]=variable
            ctk.CTkCheckBox(frame,text=address,variable=variable,command=lambda a=address:self.changed(a)).pack(anchor='w',padx=8,pady=5)
        self.message=ctk.CTkLabel(self,text='',justify='left');self.message.pack(anchor='w',padx=16)
        actions=ctk.CTkFrame(self);actions.pack(fill='x',padx=16,pady=12)
        ctk.CTkButton(actions,text='Clear selection',command=self.clear).pack(side='left',padx=5,pady=5)
        ctk.CTkButton(actions,text='Select all',command=self.select_all).pack(side='left',padx=5,pady=5)
        ctk.CTkButton(actions,text='Use selection',command=self.apply).pack(side='right',padx=5,pady=5)
        self.changed(None)

    def selected(self):
        return [address for address,value in self.variables.items() if value.get()]

    def changed(self, address):
        if address and self.variables[address].get():
            if self.limit==1:
                for other,value in self.variables.items():
                    if other!=address:value.set(False)
            elif len(self.selected())>self.limit:
                self.variables[address].set(False)
                self.message.configure(text=f'The limit is {self.limit}. Clear another device first.')
                return
        self.message.configure(text=f'{len(self.selected())} selected of {len(self.variables)} listed.')

    def clear(self):
        for value in self.variables.values():value.set(False)
        self.changed(None)

    def select_all(self):
        if len(self.variables)>self.limit:
            self.message.configure(text=f'The list has {len(self.variables)} devices. Select up to {self.limit} individually.')
            return
        for value in self.variables.values():value.set(True)
        self.changed(None)

    def apply(self):
        chosen=self.selected()
        if not 1<=len(chosen)<=self.limit:
            self.message.configure(text=f'Select between 1 and {self.limit} devices.')
            return
        self.on_apply(chosen)
        self.destroy()
