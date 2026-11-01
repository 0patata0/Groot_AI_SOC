"""Fetch bounded official incident references, preserving raw provenance and tables.

Never follow links in incident payloads, execute samples, or admit training rows.
HTML/PDF extraction is a review aid, not a verified answer key.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import re
import ssl
import threading
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from collect_defensive_sources import now, sha, write

HOSTS={'www.cyber.gov.au','cert.cyber.gouv.fr'}
LIMIT=16*1024*1024


def validate_url(url):
    u=urlsplit(url)
    if u.scheme!='https' or u.hostname not in HOSTS or u.username or u.password or u.port not in (None,443):
        raise ValueError('Unapproved reference URL')


def extract(data, kind):
    if kind=='pdf':
        import pymupdf
        with pymupdf.open(stream=data,filetype='pdf') as doc:
            pages=[{'page':i+1,'text':p.get_text(),'images':len(p.get_images())} for i,p in enumerate(doc)]
            return {'pages':pages,'page_count':len(pages),'sparse_pages':[p['page'] for p in pages if len(p['text'].strip())<80],
                    'visual_review_required':True,'training_admitted':False}
    from lxml import html
    doc=html.fromstring(data)
    for x in doc.xpath('//script|//style|//nav|//footer|//header|//form|//iframe'):x.drop_tree()
    # Keep complete article/main including tables and headings; do not flatten gold into prompts.
    nodes=doc.xpath('//article') or doc.xpath('//main')
    if len(nodes)!=1:raise ValueError('Article/main boundary needs manual review')
    node=nodes[0]
    return {'title':' '.join(doc.xpath('//h1//text()')).strip(),
            'text':node.text_content(),'article_html':html.tostring(node,encoding='unicode'),
            'headings':[{'tag':x.tag,'text':x.text_content()} for x in node.xpath('.//h2|.//h3|.//h4')],
            'tables':len(node.xpath('.//table')),'training_admitted':False}


def collect(root,spec_path):
    root=Path(root).resolve()
    if not root.name.startswith('data-'):raise ValueError('Use an ignored data-* folder')
    entries=json.loads(Path(spec_path).read_text())['sources']
    if len(entries)>20:raise ValueError('Collection budget exceeded')
    context=ssl.create_default_context(cafile='/etc/ssl/cert.pem' if Path('/etc/ssl/cert.pem').exists() else None)
    raw=root/'incident/raw';derived=root/'incident/extracted'
    raw.mkdir(parents=True,exist_ok=True);derived.mkdir(parents=True,exist_ok=True)
    receipt=root/'incident/acquisition.json'
    previous={f['id']:f for f in json.loads(receipt.read_text())['files']} if receipt.exists() else {}
    budget_lock=threading.Lock();used=[0]
    def consume(n):
        with budget_lock:
            if used[0]+n>64*1024*1024:raise ValueError('Total budget exceeded')
            used[0]+=n
    def fetch(e):
        validate_url(e['url'])
        if not re.fullmatch('[a-zA-Z0-9_-]+',e['id']) or e['format'] not in ('html','pdf'):raise ValueError('Invalid source identifier')
        p=raw/(e['id']+'.'+e['format'])
        if p.is_symlink() or not p.resolve().is_relative_to(root):raise ValueError('Unsafe destination')
        if p.exists():
            if p.stat().st_size>LIMIT:raise ValueError('File exceeds bound')
            data=p.read_bytes();consume(len(data));final=e['url'];reused=True
            if e['id'] not in previous or sha(data)!=previous[e['id']]['sha256']:
                raise ValueError('Existing raw file has no matching acquisition receipt')
        else:
            with urlopen(Request(e['url'],headers={'User-Agent':'Groot-SOC-source-review/1.0','Accept-Encoding':'identity'}),context=context,timeout=30) as resp:
                validate_url(resp.url);final=resp.url;chunks=[];size=0
                while True:
                    part=resp.read(min(65536,LIMIT+1-size))
                    if not part:break
                    consume(len(part));chunks.append(part);size+=len(part)
                    if size>LIMIT:raise ValueError('File exceeds bound')
                data=b''.join(chunks)
            reused=False
        if len(data)>LIMIT:raise ValueError('File exceeds bound')
        if e['format']=='pdf' and not data.startswith(b'%PDF-'):raise ValueError('Not PDF')
        if not reused:p.write_bytes(data)
        result={**e,'resolved_url':final,'sha256':sha(data),'bytes':len(data),'at_kst':now(),'reused':reused,'training_admitted':False}
        try:
            value=extract(data,e['format']);out=derived/(e['id']+'.json');write(out,value)
            result['extracted_sha256']=sha(out.read_bytes())
            result['extraction_status']='needs_visual_review' if e['format']=='pdf' else 'body_and_tables_preserved'
            if e['format']=='pdf':result.update(pages=value['page_count'],sparse_pages=value['sparse_pages'])
            else:result.update(tables=value['tables'],headings=len(value['headings']),title=value['title'])
        except Exception as ex:result['extraction_status']='held';result['extraction_error']=type(ex).__name__
        return result
    results=[];errors=[]
    # Bound concurrent requests and shared bytes, including data from failed parses.
    with ThreadPoolExecutor(max_workers=4) as pool:
        for offset in range(0,len(entries),4):
            if sum(x['bytes'] for x in results)>64*1024*1024:raise ValueError('Total budget exceeded')
            futures={pool.submit(fetch,e):e for e in entries[offset:offset+4]}
            for future in as_completed(futures):
                e=futures[future]
                try:results.append(future.result())
                except Exception as ex:errors.append({'id':e['id'],'url':e['url'],'error':type(ex).__name__})
    report={'at_kst':now(),'files':sorted(results,key=lambda x:x['id']),'errors':errors,
            'files_acquired':len(results),'bytes':sum(x['bytes'] for x in results),'status':'partial' if errors else 'acquired',
            'training_admitted':0,'executed_source_commands':False,
            'limits':['Provider narratives contain hindsight and third-party material; no automatic gold generation',
                      'Real case studies, campaign reports and guidance are not interchangeable counts of incidents',
                      'Legal/source-span and historical overlap review required before SFT']}
    write(root/'incident/acquisition.json',report)
    return {k:v for k,v in report.items() if k!='files'}


def review_cached(root):
    root=Path(root);report=json.loads((root/'incident/acquisition.json').read_text());results=[]
    for item in report['files']:
        data=(root/'incident/raw'/(item['id']+'.'+item['format'])).read_bytes()
        if len(data)!=item['bytes'] or sha(data)!=item['sha256']:raise ValueError('Acquired reference changed')
        result=extract(data,item['format']);out=root/'incident/extracted'/(item['id']+'.json');write(out,result)
        results.append({'id':item['id'],'extracted_sha256':sha(out.read_bytes()),'raw_sha256_verified':True})
    result={'at_kst':now(),'verified':results,'training_admitted':0,'visual_review_complete':False}
    write(root/'incident/review.json',result);return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True)
    p.add_argument('--spec',type=Path,default=Path(__file__).with_name('INCIDENT_SOURCE_SPEC.json'))
    p.add_argument('--phase',choices=('collect','review'),default='collect')
    a=p.parse_args();print(json.dumps(collect(a.root,a.spec) if a.phase=='collect' else review_cached(a.root),ensure_ascii=False))
