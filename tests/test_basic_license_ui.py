"""Exercise Basic's real device selection and import workflow without network access."""
import time
import tkinter
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.test_basic_licensing import signed_license


@pytest.fixture
def basic_ui(tmp_path,monkeypatch,signed_license):
    monkeypatch.setenv('WIN_PD_OVERRIDE_PERSONAL',str(tmp_path/'Documents'))
    monkeypatch.setenv('STIG_AUDIT_BASIC_LICENSE_PATH',str(tmp_path/'basic.json'))
    import customtkinter as ctk
    from stig_audit_pro.basic_app import BasicApp
    from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
    try:root=ctk.CTk()
    except tkinter.TclError as exc:pytest.skip(f'Tk display unavailable: {exc}')
    root.withdraw()
    app=BasicApp(root)
    app.license_policy=BasicLicensePolicy(signed_license[0])
    messages=[]
    app.messagebox=SimpleNamespace(**{name:lambda *args:messages.append(args) for name in ('showerror','showinfo','showwarning')})
    app.refresh_license_status()
    yield app,root,messages
    if app.thread is not None:app.thread.join(timeout=10)
    for callback in root.tk.call('after','info'):root.tk.call('after','cancel',callback)
    root.destroy()


def fill_inventory(app):
    inventory='192.0.2.10\n192.0.2.26\n192.0.2.30\n'
    app.devices.delete('1.0','end');app.devices.insert('1.0',inventory)
    app.sync_selected_devices()
    return inventory


def test_free_selection_runs_only_chosen_device_and_retains_inventory(basic_ui,tmp_path):
    app,root,messages=basic_ui
    inventory=fill_inventory(app)
    app.select_devices()
    dialog=app.selection_dialog
    dialog.variables['192.0.2.26'].set(True);dialog.changed('192.0.2.26');dialog.apply()
    assert app.selected_addresses==['192.0.2.26']
    assert app.devices.get('1.0','end').strip()==inventory.strip()
    app.mode.set('Sample outputs');app.family.set('L2');app.ckl_var.set(False)
    output=tmp_path/'reports';app.output_dir.delete(0,'end');app.output_dir.insert(0,str(output))
    app.start()
    assert app.thread is not None,messages
    deadline=time.monotonic()+10
    while app.thread.is_alive() and time.monotonic()<deadline:
        root.update();time.sleep(.02)
    assert not app.thread.is_alive()
    reports=list(output.glob('*.txt'))
    assert len(reports)==1
    assert '192.0.2.26' in reports[0].read_text()
    assert app.devices.get('1.0','end').strip()==inventory.strip()


def test_licensed_selector_allows_limit_without_removing_unselected_devices(basic_ui,signed_license):
    app,_,_=basic_ui
    _,issue,_=signed_license;issue(maximum=2)
    inventory=fill_inventory(app)
    app.select_devices();dialog=app.selection_dialog
    dialog.variables['192.0.2.26'].set(True);dialog.changed('192.0.2.26')
    dialog.variables['192.0.2.30'].set(True);dialog.changed('192.0.2.30')
    dialog.apply()
    assert app.selected_addresses==['192.0.2.10','192.0.2.26']
    assert app.devices.get('1.0','end').strip()==inventory.strip()


def test_license_import_rejects_tampering_and_keeps_previous_license(basic_ui,signed_license,tmp_path):
    app,_,messages=basic_ui
    manager,issue,_=signed_license
    issue(maximum=2)
    original=manager.license_path.read_bytes()
    candidate=tmp_path/'bad.license.json'
    candidate.write_bytes(original.replace(b'Test Customer',b'Fake Customer'))
    app.filedialog=SimpleNamespace(askopenfilename=lambda **kwargs:str(candidate))
    app.import_license_file()
    assert manager.license_path.read_bytes()==original
    assert messages[-1][0]=='License not imported'


def test_license_import_updates_visible_limit(basic_ui,signed_license,tmp_path):
    app,_,_=basic_ui
    manager,issue,_=signed_license
    issue(maximum=7)
    candidate=tmp_path/'valid.license.json';candidate.write_bytes(manager.license_path.read_bytes())
    manager.license_path.unlink()
    app.filedialog=SimpleNamespace(askopenfilename=lambda **kwargs:str(candidate))
    app.import_license_file()
    assert app.license_panel.values['limit'].cget('text')=='7'
    assert app.license_panel.values['customer'].cget('text')=='Test Customer'
    assert app.license_policy.device_limit==7


def test_select_all_obeys_batch_limit(basic_ui,signed_license):
    app,_,_=basic_ui
    _,issue,_=signed_license
    fill_inventory(app);app.select_devices()
    dialog=app.selection_dialog;dialog.select_all()
    assert dialog.selected()==['192.0.2.10']
    dialog.destroy()
    issue(maximum=3);app.select_devices();dialog=app.selection_dialog
    dialog.select_all();dialog.apply()
    assert app.selected_addresses==['192.0.2.10','192.0.2.26','192.0.2.30']


def test_removing_selected_device_does_not_silently_scan_another(basic_ui):
    app,_,messages=basic_ui
    fill_inventory(app)
    app.apply_device_selection(['192.0.2.26'])
    app.devices.delete('1.0','end');app.devices.insert('1.0','192.0.2.30\n192.0.2.40')
    app.sync_selected_devices()
    assert app.selected_addresses==[]
    app.start()
    assert app.thread is None
    assert 'select' in messages[-1][1].lower()
