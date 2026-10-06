"""Combined reports for devices in one Basic audit run."""
from __future__ import annotations
import csv
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from stig_audit_pro.reports.spreadsheet_safety import safe_spreadsheet_row

STATUSES=("Open","NotAFinding","Error","Skipped","Not_Applicable","Not_Reviewed")
CATS=("CAT I","CAT II","CAT III","Other")
COLORS={"Open":"#b42318","NotAFinding":"#16803c","Error":"#a16b00",
        "Skipped":"#637083","Not_Applicable":"#526e92","Not_Reviewed":"#7b48a4"}

def cat(value):
    key=str(value).lower().replace(' ','').replace('-','')
    return {'cat1':'CAT I','cati':'CAT I','high':'CAT I','1':'CAT I',
            'cat2':'CAT II','catii':'CAT II','medium':'CAT II','2':'CAT II',
            'cat3':'CAT III','catiii':'CAT III','low':'CAT III','3':'CAT III'}.get(key,'Other')

@dataclass(frozen=True)
class Filter:
    statuses:frozenset[str]=frozenset(STATUSES)
    cats:frozenset[str]=frozenset(CATS)
    devices:frozenset[str]|None=None
    families:frozenset[str]|None=None

def summarize(results, filters:Filter, targets=()):
    results=list(results)
    details=sorted((r for r in results if r.status in filters.statuses and cat(r.severity) in filters.cats
                    and (filters.devices is None or r.ip in filters.devices)
                    and (filters.families is None or r.stig_family in filters.families)),
                   key=lambda r:(r.ip,CATS.index(cat(r.severity)),r.status,r.vuln_id))
    status=Counter(r.status for r in results)
    addresses=sorted(set(targets)|{r.ip for r in results})
    open_by_device=defaultdict(Counter)
    for ip in addresses:open_by_device[ip]
    for r in results:
        if r.status=='Open':open_by_device[r.ip][cat(r.severity)]+=1
    assessed=status['Open']+status['NotAFinding']
    return dict(results=results,details=details,filters=filters,devices=len(addresses),
                addresses=addresses,unassessed=sorted(set(addresses)-{r.ip for r in results}),
                status=status,open_by_device=dict(open_by_device),
                open_by_cat=Counter(cat(r.severity) for r in results if r.status=='Open'),
                checks=len(results),pass_rate=round(100*status['NotAFinding']/assessed,1) if assessed else None,
                coverage=round(100*assessed/len(results),1) if results else None,
                generated=datetime.now(timezone.utc))

def _detail(r):
    return [r.hostname,r.ip,r.stig_family,cat(r.severity),r.status,r.vuln_id,r.title,
            r.finding_details,r.comments,r.evaluation_reason,r.error_message or '']

def export_csv(report,path):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.writer(f)
        writer.writerow(['Switch','IP','Family','Category','Status','Vuln ID','Title',
                         'Finding details','Comments','Evaluation reason','Error'])
        for r in report['details']:writer.writerow(safe_spreadsheet_row(_detail(r)))
    return path

def _bars(items):
    maximum=max((n for _,n,_ in items),default=0) or 1
    lines=[f'<svg viewBox="0 0 620 {35*len(items)+8}" role="img" aria-label="Count chart">']
    for i,(label,count,color) in enumerate(items):
        y=4+35*i;width=round(380*count/maximum)
        lines.append(f'<text x="0" y="{y+18}">{escape(label)}</text><rect x="165" y="{y+3}" width="{width}" height="20" fill="{color}"/><text x="{175+width}" y="{y+18}">{count}</text>')
    return ''.join(lines)+'</svg>'

def export_html(report,path):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    status_chart=_bars([(s,report['status'][s],COLORS[s]) for s in STATUSES])
    cat_chart=_bars([(c,report['open_by_cat'][c],'#b42318') for c in CATS[:3]])
    switches=[]
    for ip in report['addresses']:
        name=next((r.hostname for r in report['results'] if r.ip==ip),'Unassessed')
        counts=report['open_by_device'][ip]
        switches.append('<tr>'+''.join(f'<td>{escape(str(x))}</td>' for x in
            (name,ip,*[counts[c] for c in CATS[:3]],sum(counts.values())))+'</tr>')
    detail_rows=['<tr>'+''.join(f'<td>{escape(str(x))}</td>' for x in _detail(r))+'</tr>' for r in report['details']]
    f=report['filters']
    selected=f"Statuses: {', '.join(sorted(f.statuses))}; CAT: {', '.join(sorted(f.cats))}; devices: {', '.join(sorted(f.devices)) if f.devices else 'All'}; families: {', '.join(sorted(f.families)) if f.families else 'All'}"
    html=f'''<!doctype html><html lang="en"><meta charset="utf-8"><title>Overall audit summary</title>
<style>body{{font:15px/1.5 Segoe UI,Arial;max-width:1300px;margin:32px auto;padding:0 20px;color:#192535}}h1,h2{{color:#12334d}}.note{{background:#fff8e5;padding:12px;border-left:4px solid #a87600}}svg{{max-width:620px;width:100%;height:auto}}table{{border-collapse:collapse;width:100%;font-size:12px}}td,th{{border:1px solid #cad5df;padding:6px;text-align:left;vertical-align:top;overflow-wrap:anywhere}}th{{background:#e8eff5}}.scroll{{overflow-x:auto}}@media print{{tr{{break-inside:avoid}}}}</style>
<h1>Overall audit summary</h1><p>Current audit run only. Generated {report['generated'].strftime('%Y-%m-%d %H:%M UTC')}.</p>
<p><b>{report['devices']} devices · {report['checks']} checks · {report['status']['Open']} open · {report['pass_rate'] if report['pass_rate'] is not None else 'N/A'}% assessed pass rate · {report['coverage'] if report['coverage'] is not None else 'N/A'}% assessment coverage</b></p>
<p class="note">Pass rate uses only Not a Finding and Open results. Coverage is those two statuses divided by all emitted results. Error, Skipped, Not Reviewed, and Not Applicable remain separate. Devices with no check results: {escape(', '.join(report['unassessed']) or 'None')}. These numbers describe this audit, not comprehensive network health.</p>
<h2>All results by status</h2>{status_chart}<h2>Open findings by category</h2>{cat_chart}
<h2>Open findings by switch</h2><div class="scroll"><table><tr><th>Switch</th><th>IP</th><th>CAT I</th><th>CAT II</th><th>CAT III</th><th>All open</th></tr>{''.join(switches)}</table></div>
<h2>Filtered check details</h2><p>{escape(selected)}. {len(report['details'])} matching results.</p>
<div class="scroll"><table><tr>{''.join('<th>'+escape(x)+'</th>' for x in ['Switch','IP','Family','Category','Status','Vuln ID','Title','Finding details','Comments','Evaluation reason','Error'])}</tr>{''.join(detail_rows)}</table></div></html>'''
    path.write_text(html,encoding='utf-8');return path

def export_pdf(report,path):
    from reportlab.graphics.shapes import Drawing,Rect,String
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,KeepTogether
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    styles=getSampleStyleSheet();story=[Paragraph('Overall audit summary',styles['Title']),
        Paragraph('Current audit run only. Generated '+report['generated'].strftime('%Y-%m-%d %H:%M UTC'),styles['Normal']),Spacer(1,10)]
    def section(title):story.extend([Spacer(1,12),Paragraph(title,styles['Heading2'])])
    def chart(items):
        d=Drawing(480,len(items)*26+4);top=len(items)*26;maximum=max((n for _,n,_ in items),default=0) or 1
        for i,(label,n,color) in enumerate(items):
            y=top-i*26-20;d.add(String(0,y+5,label,fontSize=9));d.add(Rect(110,y,300*n/maximum,16,fillColor=colors.HexColor(color),strokeColor=None));d.add(String(420,y+5,str(n),fontSize=9))
        story.append(d)
    def table(rows,widths):
        t=Table(rows,colWidths=widths,repeatRows=1,hAlign='LEFT')
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e8eff5')),
            ('GRID',(0,0),(-1,-1),.35,colors.HexColor('#cad5df')),('VALIGN',(0,0),(-1,-1),'TOP'),('FONTSIZE',(0,0),(-1,-1),8)]))
        story.append(t)
    rate=str(report['pass_rate'])+'%' if report['pass_rate'] is not None else 'N/A'
    coverage=str(report['coverage'])+'%' if report['coverage'] is not None else 'N/A'
    table([['Devices','Checks','Open','Assessed pass rate','Coverage'],[report['devices'],report['checks'],report['status']['Open'],rate,coverage]],[55,55,50,145,145])
    story.append(Spacer(1,8));story.append(Paragraph('Pass rate uses Not a Finding and Open only. Errors and review gaps stay separate. Unassessed devices: '+escape(', '.join(report['unassessed']) or 'None')+'. This is not a full network health score.',styles['Normal']))
    section('All results by status');chart([(s,report['status'][s],COLORS[s]) for s in STATUSES])
    section('Open findings by category');chart([(c,report['open_by_cat'][c],'#b42318') for c in CATS[:3]])
    section('Open findings by switch')
    rows=[['Switch / IP','CAT I','CAT II','CAT III','All open']]
    for ip in report['addresses']:
        name=next((r.hostname for r in report['results'] if r.ip==ip),'Unassessed');counts=report['open_by_device'][ip]
        rows.append([Paragraph(escape(name+' / '+ip),styles['Normal']),*[counts[c] for c in CATS[:3]],sum(counts.values())])
    table(rows,[225,55,55,55,60]);section('Filtered check details')
    story.append(Paragraph(f"{len(report['details'])} matching of {report['checks']} results",styles['Normal']))
    for r in report['details']:
        block=[Paragraph(escape(f'{r.ip} · {r.vuln_id} · {cat(r.severity)} · {r.status} · {r.stig_family}'),styles['Heading4']),Paragraph(escape(r.title),styles['Normal'])]
        for label,value in [('Finding',r.finding_details),('Comments',r.comments),('Reason',r.evaluation_reason),('Error',r.error_message)]:
            if value:block.append(Paragraph(escape(label+': '+value),styles['Normal']))
        block.append(Spacer(1,5));story.append(KeepTogether(block))
    if not report['details']:story.append(Paragraph('No results match the selected filters.',styles['Normal']))
    SimpleDocTemplate(str(path),pagesize=(8.5*inch,11*inch),leftMargin=40,rightMargin=40,topMargin=42,bottomMargin=42).build(story)
    return path
