# Rebuild the Basic edition on Windows with Python 3.12.
from PyInstaller.utils.hooks import collect_data_files
a = Analysis(['app.py'], pathex=[], binaries=[], datas=[('data','data'),('tests/sample_outputs','tests/sample_outputs'),('stig_audit_pro/resources/licensing/public_keys','stig_audit_pro/resources/licensing/public_keys')] + collect_data_files('customtkinter'), hiddenimports=[], hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=["tools", "tools.license_admin"], noarchive=False, optimize=0)
pyz = PYZ(a.pure)
exe = EXE(pyz,a.scripts,[],exclude_binaries=True,name='STIG Audit Basic',debug=False,bootloader_ignore_signals=False,strip=False,upx=False,console=False,disable_windowed_traceback=False)
coll = COLLECT(exe,a.binaries,a.datas,strip=False,upx=False,name='STIG Audit Basic')
