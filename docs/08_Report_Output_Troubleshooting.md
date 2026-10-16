# Basic report output and failed audits

Select a writable output folder on the Audit tab before starting. A completed
audit lists the full paths and count of encrypted `.sapenc` files it wrote.
The **Run & Review** card shows the current state, actual protected-file
count, failed-device count, and exact output folder. **Open output folder**
opens that destination. **View latest protected report** opens the current
run's most recent text report in Results without creating a readable file.
Two devices with the same last IP octet have distinct filenames; the file
stem includes a safe form of the complete target and a short digest.

If no device completed collection or evaluation, Basic says **Audit failed**
and lists the affected device and a safe reason. It does not claim files were
written. If some devices succeeded, it says **Partial audit**, lists the
files that exist, and identifies devices without a completed assessment.
Do not treat a failed device as compliant or import a partial CKL as complete.
If report writing fails after an earlier file was saved, Basic reports a
partial audit and lists the files that exist. A Summary export similarly
reports any protected files saved before a later format failed.

For live SSH, Basic currently has host-key verification disabled for temporary
compatibility. Confirm the address, port, account, and network path through
your approved pilot process before collection. Other failures can be caused by
credentials, reachability, device access, or invalid site settings. Recheck
the Audit tab's selection and the reported device outcome, then retry after
correcting the cause. Host-key verification should be restored before a
production deployment.

The `.sapenc` file is ciphertext. Use **Results → Open protected report** to
read supported text formats in Basic. **Export readable copy** deliberately
creates an unencrypted file for STIG Viewer or another approved tool.
An exported copy is outside the Basic vault. A protected file cannot be
renamed without invalidating its authenticated file association. Reports
from old Basic versions are not converted automatically.
