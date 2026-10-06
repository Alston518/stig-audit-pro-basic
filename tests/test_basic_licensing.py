"""Basic's free single-device contract and signed-license enforcement."""
import base64
import json
import queue
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stig_audit_pro.licensing import LicenseManager, LicensePolicyError, LicenseImportError
from stig_audit_pro.licensing.canonicalize import canonicalize_license
from stig_audit_pro.storage.device_groups import DeviceTargetRecord

NOW = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
FEATURES = ['l2_checks', 'ndm_checks', 'ckl_export', 'advanced_reporting', 'multi_device_scan']


@pytest.fixture
def signed_license(tmp_path):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    clock = [NOW]
    manager = LicenseManager(tmp_path/'installed.json', public_key_loader=lambda _: public, now_provider=lambda: clock[0])

    def issue(*, maximum=3, features=FEATURES, expires=NOW+timedelta(days=1), tamper=False):
        payload = dict(schema_version=1, license_id='BASIC-QA', customer_name='Test Customer', product='STIG Audit Pro', edition='Basic', issued_at=(NOW-timedelta(days=2)).isoformat(), expires_at=expires.isoformat(), max_devices=maximum, features={x:x in features for x in FEATURES})
        signature = base64.b64encode(key.sign(canonicalize_license(payload))).decode()
        if tamper: payload['max_devices'] = 999
        document = dict(license=payload, signature=dict(algorithm='Ed25519', key_id='qa', value=signature))
        manager.license_path.write_text(json.dumps(document))
        manager.reload()
        return manager
    return manager, issue, clock


@pytest.mark.parametrize('state', ['missing', 'expired', 'tampered'])
def test_unlicensed_states_allow_one_real_device_and_both_reports(signed_license, state):
    from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
    manager, issue, _ = signed_license
    if state=='expired': issue(expires=NOW-timedelta(days=1))
    if state=='tampered': issue(tamper=True)
    policy = BasicLicensePolicy(manager)
    assert policy.validate(['192.0.2.7'], ['ios_l2','ios_ndm'], True, True)==('192.0.2.7',)
    with pytest.raises(LicensePolicyError):
        policy.validate(['192.0.2.7','192.0.2.8'], ['iosxe_l2'], True, True)


def test_valid_license_allows_exact_limit_and_rejects_one_more(signed_license):
    from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
    _, issue, _ = signed_license
    policy = BasicLicensePolicy(issue(maximum=2))
    assert policy.validate(['192.0.2.1','192.0.2.2'], ['iosxe_ndm'], True, True)==('192.0.2.1','192.0.2.2')
    with pytest.raises(LicensePolicyError):
        policy.validate(['192.0.2.1','192.0.2.2','192.0.2.3'], ['iosxe_ndm'], True, True)


@pytest.mark.parametrize('flag,families,txt,ckl', [
    ('l2_checks',['ios_l2'],True,False), ('l2_checks',['iosxe_l2'],True,False),
    ('ndm_checks',['ios_ndm'],True,False), ('ndm_checks',['iosxe_ndm'],True,False),
    ('ckl_export',['ios_l2'],False,True), ('advanced_reporting',['ios_l2'],True,False),
])
def test_valid_license_enforces_each_requested_feature(signed_license, flag, families, txt, ckl):
    from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
    _, issue, _ = signed_license
    policy = BasicLicensePolicy(issue(features=[x for x in FEATURES if x!=flag]))
    with pytest.raises(LicensePolicyError):
        policy.validate(['192.0.2.1'], families, txt, ckl)


def test_no_multi_device_flag_limits_valid_license_to_one(signed_license):
    from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
    _, issue, _ = signed_license
    policy = BasicLicensePolicy(issue(maximum=100,features=FEATURES[:-1]))
    assert policy.validate(['SW1.example'], ['ios_l2'], True, True)==('sw1.example',)
    with pytest.raises(LicensePolicyError):
        policy.validate(['SW1.example','SW2.example'], ['ios_l2'], True, True)


def test_expiration_rechecked_with_same_policy_instance(signed_license):
    from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
    _, issue, clock = signed_license
    policy = BasicLicensePolicy(issue(expires=NOW+timedelta(seconds=1)))
    policy.validate(['192.0.2.1','192.0.2.2'], ['ios_l2'], True, True)
    clock[0] += timedelta(seconds=2)
    with pytest.raises(LicensePolicyError):
        policy.validate(['192.0.2.1','192.0.2.2'], ['ios_l2'], True, True)
    assert policy.validate(['192.0.2.2'], ['ios_ndm'], True, True)==('192.0.2.2',)


def test_duplicate_ips_and_hostnames_are_counted_once(signed_license):
    from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
    manager, _, _ = signed_license
    policy = BasicLicensePolicy(manager)
    assert policy.validate(['SW1.EXAMPLE','sw1.example.'], ['ios_l2'], True, True)==('sw1.example',)
    assert policy.validate(['2001:db8::1','2001:db8:0:0:0:0:0:1'], ['ios_l2'], True, True)==('2001:db8::1',)
    with pytest.raises(LicensePolicyError):policy.validate(['bad host'], ['ios_l2'], True, True)


def test_non_utf8_license_falls_back_to_single_device(signed_license):
    from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
    manager, _, _ = signed_license
    manager.license_path.write_bytes(b'\xff\xfeinvalid license')
    policy=BasicLicensePolicy(manager)
    assert policy.summary()['status']=='INVALID'
    assert policy.validate(['192.0.2.1'],['ios_l2'],True,True)==('192.0.2.1',)
    with pytest.raises(LicensePolicyError):
        policy.validate(['192.0.2.1','192.0.2.2'],['ios_l2'],True,True)


@pytest.mark.parametrize('targets,families,txt,ckl', [([],['ios_l2'],True,False),(['192.0.2.1'],['unknown_l2'],True,False),(['192.0.2.1'],['ios_l2'],False,False)])
def test_invalid_requests_are_rejected(signed_license, targets, families, txt, ckl):
    from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
    manager, _, _ = signed_license
    with pytest.raises(LicensePolicyError):BasicLicensePolicy(manager).validate(targets,families,txt,ckl)


def test_worker_rejects_unlicensed_batch_before_collection(signed_license, monkeypatch, tmp_path):
    from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
    from stig_audit_pro.basic_app import BasicApp
    from stig_audit_pro.application.audit_service import AuditService
    manager, _, _ = signed_license
    app=BasicApp.__new__(BasicApp)
    app.license_policy=BasicLicensePolicy(manager)
    app.events=queue.Queue();app.cancel_event=threading.Event()
    calls=[]
    monkeypatch.setattr(AuditService,'run_live',lambda *a,**kw:calls.append('connected'))
    app._run([DeviceTargetRecord(ip='192.0.2.1'),DeviceTargetRecord(ip='192.0.2.2')],[],None,None,['ios_l2'],'Live SSH',{},True,False,tmp_path/'output')
    assert calls==[]
    assert not (tmp_path/'output').exists()
    assert '1 device' in app.events.get_nowait().message


def test_license_changed_during_collection_is_rechecked_before_export(signed_license, monkeypatch, tmp_path):
    from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
    from stig_audit_pro.basic_app import BasicApp
    from stig_audit_pro.application.audit_service import AuditService
    _, issue, clock = signed_license
    app=BasicApp.__new__(BasicApp);app.license_policy=BasicLicensePolicy(issue(expires=NOW+timedelta(seconds=1)))
    app.events=queue.Queue();app.cancel_event=threading.Event()
    def collect(*a,**kw):
        clock[0]+=timedelta(seconds=2)
        return SimpleNamespace(assets={},results=[])
    monkeypatch.setattr(AuditService,'run_live',collect)
    app._run([DeviceTargetRecord(ip='192.0.2.1'),DeviceTargetRecord(ip='192.0.2.2')],[],None,None,['ios_l2'],'Live SSH',{},True,False,tmp_path/'output')
    assert not (tmp_path/'output').exists()
    assert '1 device' in app.events.get_nowait().message
