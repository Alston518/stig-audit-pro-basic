from pathlib import Path
from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.reports.basic_summary import Filter, summarize, export_csv, export_html, export_pdf
from stig_audit_pro.basic_app import load_template_paths, persist_template_paths

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
