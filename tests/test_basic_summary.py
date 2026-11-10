from pathlib import Path
import hashlib
import json
from types import SimpleNamespace
from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.reports.basic_summary import Filter, summarize, export_csv, export_html, export_pdf
from stig_audit_pro.basic_app import load_template_paths, persist_template_paths
from stig_audit_pro.basic_app import BasicApp
from stig_audit_pro.infrastructure.security.at_rest import AtRestVault
from stig_audit_pro.infrastructure.security.basic_artifacts import ProtectedArtifactStore

def item(ip, vuln, cat, status):
    return CheckResult(ip=ip, hostname='SW-'+ip[-1], vuln_id=vuln,
                       stig_family='IOSXE_L2', title='Example', severity=cat, status=status)

def test_combines_devices_and_filters_details_without_hiding_overview(tmp_path):
    rows=[item('192.0.2.1','V-1','cat1','Open'),item('192.0.2.2','V-1','cat1','Open'),
          item('192.0.2.2','V-2','cat2','NotAFinding')]
    report=summarize(rows,Filter(statuses=frozenset({'Open'}),cats=frozenset({'CAT I'})),
                     ['192.0.2.1','192.0.2.2','192.0.2.3'])
    assert report['devices']==3
    assert report['unassessed']==['192.0.2.3']
    assert report['status']['NotAFinding']==1
    assert report['open_by_device']['192.0.2.1']['CAT I']==1
    assert len(report['details'])==2
    assert export_csv(report,tmp_path/'summary.csv').is_file()
    assert '<svg' in export_html(report,tmp_path/'summary.html').read_text(encoding='utf-8')
    assert export_pdf(report,tmp_path/'summary.pdf').read_bytes().startswith(b'%PDF-')

def test_packaged_template_paths_replace_old_workspace_paths_and_follow_package_move(tmp_path):
    first=tmp_path/'first'/'Checklist Templates';second=tmp_path/'second'/'Checklist Templates'
    old=tmp_path/'Workspace'/'CKL Templates';settings=tmp_path/'Workspace'/'template_paths.json'
    for folder in (first,second,old):folder.mkdir(parents=True)
    name='IOSXE_L2_Template.ckl'
    for folder in (first,second,old):(folder/name).write_text(folder.parent.name,encoding='utf-8')
    assert load_template_paths(first,old,settings)['IOS XE']['L2']==str(first/name)
    persist_template_paths({'IOS XE':{'L2':str(first/name)}},first,settings)
    assert load_template_paths(second,old,settings)['IOS XE']['L2']==str(second/name)


def test_summary_export_has_encrypted_hash_manifest(tmp_path):
    app = BasicApp.__new__(BasicApp)
    app.last_targets = ['192.0.2.10']
    app.last_families = ['iosxe_l2']
    app.last_run_id = 'run-123'
    app.last_results = [CheckResult(
        ip='192.0.2.10', hostname='switch', vuln_id='V-1', stig_family='IOSXE_L2',
        stig_release='Release: 2 Benchmark Date: 02 Jul 2025',
        title='Example', severity='cat2', status='Open',
    )]
    app.summary_pdf = SimpleNamespace(get=lambda: False)
    app.summary_html = SimpleNamespace(get=lambda: False)
    app.summary_csv = SimpleNamespace(get=lambda: True)
    app.license_policy = SimpleNamespace(validate=lambda *_args: None)
    app._summary_filter = lambda: Filter()
    app.output_dir = SimpleNamespace(get=lambda: str(tmp_path))
    app.artifacts = ProtectedArtifactStore(AtRestVault.open(tmp_path / 'vault.json', 'test', create=True))
    app.messagebox = SimpleNamespace(showerror=lambda *_args: None, showinfo=lambda *_args: None)
    app.preview_summary = lambda: None

    reports = app.export_summary()
    assert len(reports) == 1
    manifests = list(tmp_path.glob('*.manifest.json.sapenc'))
    assert len(manifests) == 1
    manifest = json.loads(app.artifacts.read_manifest(manifests[0]))
    assert manifest['stig_release'] == app.last_results[0].stig_release
    assert manifest['file_hashes'] == {
        reports[0].name: hashlib.sha256(app.artifacts.read(reports[0])).hexdigest()
    }
