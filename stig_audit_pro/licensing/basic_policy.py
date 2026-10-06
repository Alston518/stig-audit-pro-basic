"""Basic-specific entitlements over the existing signed offline license format."""
from __future__ import annotations

import ipaddress
import os
import re
import threading
from pathlib import Path
from collections.abc import Iterable

from platformdirs import user_data_path
from stig_audit_pro.config import LICENSE_FILENAME
from stig_audit_pro.licensing import LicenseManager, LicensePolicyError

BASIC_FEATURE_LABELS = {
    'l2_checks': 'L2 checks (IOS and IOS XE)',
    'ndm_checks': 'NDM checks (IOS and IOS XE)',
    'ckl_export': 'CKL checklists',
    'advanced_reporting': 'TXT reports',
    'multi_device_scan': 'Multi-device audits',
}
FAMILY_FEATURES = {
    'ios_l2': 'l2_checks', 'iosxe_l2': 'l2_checks',
    'ios_ndm': 'ndm_checks', 'iosxe_ndm': 'ndm_checks',
}


def normalize_basic_targets(targets: Iterable[str]) -> tuple[str, ...]:
    """Count equivalent IP spellings and case-insensitive hostnames once."""
    unique = []
    seen = set()
    for raw in targets:
        target = str(raw).strip()
        try:
            target = str(ipaddress.ip_address(target))
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', target):
                raise LicensePolicyError(f'Invalid device IP address or hostname: {raw}')
            target = target.rstrip('.').casefold()
        if target not in seen:
            seen.add(target)
            unique.append(target)
    return tuple(unique)


class BasicLicensePolicy:
    """Free Basic permits a full assessment of one selected device per audit."""

    def __init__(self, manager: LicenseManager | None = None):
        license_path = os.environ.get('STIG_AUDIT_BASIC_LICENSE_PATH') or (
            user_data_path('STIG Audit Pro Basic', appauthor=False, roaming=False) / LICENSE_FILENAME
        )
        self.manager = manager if manager is not None else LicenseManager(license_path)
        self._lock = threading.RLock()
        self.refresh()

    def refresh(self):
        with self._lock:
            return self.manager.reload()

    @property
    def device_limit(self) -> int:
        with self._lock:
            if self.manager.feature_enabled('multi_device_scan'):
                return self.manager.max_devices
            return 1

    def import_license(self, path: str | Path) -> Path:
        with self._lock:
            return self.manager.import_license(path)

    def summary(self) -> dict:
        with self._lock:
            manager = self.manager
            enabled = {
                key: manager.feature_enabled(key) if manager.is_valid else key != 'multi_device_scan'
                for key in BASIC_FEATURE_LABELS
            }
            return dict(status=manager.status.value, valid=manager.is_valid,
                        customer=manager.customer_name, edition=manager.edition,
                        expires=manager.expires_at, license_id=manager.license_id,
                        device_limit=self.device_limit, signed_limit=manager.licensed_max_devices,
                        path=str(manager.license_path), features=enabled,
                        errors=manager.validation_errors)

    def validate(self, targets: Iterable[str], families: Iterable[str],
                 make_txt: bool, make_ckl: bool) -> tuple[str, ...]:
        """Validate the actual selected batch before collection and before export."""
        with self._lock:
            self.manager.reload()
            normalized = normalize_basic_targets(targets)
            if not normalized:
                raise LicensePolicyError('Select at least one device to audit.')
            limit = self.device_limit
            if len(normalized) > limit:
                raise LicensePolicyError(
                    f'This license permits {limit} device(s) per audit; {len(normalized)} are selected. '
                    'Keep your full device list and use Select devices to choose a smaller batch.'
                )
            selected_families = tuple(families)
            if not selected_families or any(x not in FAMILY_FEATURES for x in selected_families):
                raise LicensePolicyError('Select a supported IOS or IOS XE L2/NDM assessment.')
            if not make_txt and not make_ckl:
                raise LicensePolicyError('Select TXT report, CKL checklist, or both.')
            if self.manager.is_valid:
                needed = {FAMILY_FEATURES[x] for x in selected_families}
                if make_txt: needed.add('advanced_reporting')
                if make_ckl: needed.add('ckl_export')
                for feature in sorted(needed):
                    if not self.manager.feature_enabled(feature):
                        raise LicensePolicyError(
                            f'{BASIC_FEATURE_LABELS[feature]} is not enabled by the installed license. '
                            'Change the audit selection or import a license with this feature.'
                        )
            return normalized
