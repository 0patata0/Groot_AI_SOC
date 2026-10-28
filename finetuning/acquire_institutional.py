"""Acquire pinned institutional SOC evidence directly on the training host.

Full mode checks published archive MD5 plus local SHA256. Range mode checks
selected member CRC/SHA and unchanged record metadata, not whole-archive MD5.
Only named raw/label members are retained after CRC and SHA verification. Never
extract arbitrary paths, install packages, touch GPUs or stop services.
"""
import argparse,concurrent.futures,hashlib,json,os,re,shutil,time,zipfile
from pathlib import Path
from urllib import request
from datetime import datetime,timezone,timedelta
from remote_zip import RemoteZip

def now():return datetime.now(timezone(timedelta(hours=9))).isoformat()
def save(path,value):
 temp=path.with_suffix('.tmp');temp.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n');temp.replace(path)
def sha(data):return hashlib.sha256(data).hexdigest()
def verified_copy(stream,path,size,md5,*,progress=None,deadline=None):
 h=hashlib.md5();s=hashlib.sha256();count=0;tick=0
 with path.open('xb') as out:
  while True:
   if deadline and time.monotonic()>deadline:raise TimeoutError('Acquisition time limit')
   data=stream.read(4*1024*1024)
   if not data:break
   count+=len(data)
   if count>size:raise ValueError('Source larger than pinned metadata')
   out.write(data);h.update(data);s.update(data)
   if count-tick>=256*1024*1024:
    tick=count
    if shutil.disk_usage(path.parent).free<8*2**30:raise ValueError('Preserve host disk reserve')
    if progress:progress(count)
 if count!=size or h.hexdigest()!=md5:raise ValueError('Published archive checksum/length mismatch')
 return {'bytes':count,'md5':h.hexdigest(),'sha256':s.hexdigest(),'whole_archive_checksum_verified':True}

def member_names(archive):
 names=['gather/attacker_0/logs/attacks.log']
 for host in ('intranet_server','webserver','mail','inet-firewall'):
  for log in ('auth.log','audit/audit.log'):
   for prefix in ('gather','labels'):
    name=prefix+'/'+host+'/logs/'+log
    if name in archive.namelist():names.append(name)
 mandatory=['gather/intranet_server/logs/audit/audit.log','labels/intranet_server/logs/audit/audit.log']
 if not all(n in names for n in mandatory):raise ValueError('Required raw audit/line-label pair absent')
 return names

def retain_members(path,destination):
 destination.mkdir(exist_ok=False);receipts=[]
 with zipfile.ZipFile(path) as archive:
  for name in member_names(archive):
   info=archive.getinfo(name);rel=Path(name)
   if info.is_dir() or rel.is_absolute() or '..' in rel.parts or info.file_size>32*1024*1024:raise ValueError('Unsafe archive member')
   data=archive.read(info) # ZipFile verifies the selected member CRC.
   out=destination/rel;out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(data)
   receipts.append({'path':name,'bytes':len(data),'sha256':sha(data),'crc32':f'{info.CRC:08x}','zip_crc_verified':True})
 return receipts

def acquire_environment(folder,entry):
 env=entry['key'].removesuffix('.zip');state={'environment':env,'status':'downloading','started_at_kst':now(),'source_url':entry['links']['self'],'published_checksum':entry['checksum'],'expected_bytes':entry['size'],'downloaded_bytes':0};record=folder/(env+'-acquisition.json');save(record,state)
 archive=folder/(env+'.acquisition.zip')
 try:
  deadline=time.monotonic()+1800;url=entry['links']['self']
  if not re.fullmatch(r'https://zenodo.org/api/records/5789064/files/[a-z]+\.zip/content',url):raise ValueError('Unexpected institutional source URL')
  req=request.Request(url,headers={'User-Agent':'SOC-research-provenance/1.0','Accept-Encoding':'identity'})
  def progress(n):state.update(downloaded_bytes=n,updated_at_kst=now());save(record,state)
  with request.urlopen(req,timeout=60) as stream:
   if stream.status!=200:raise ValueError('Full archive HTTP status mismatch')
   proof=verified_copy(stream,archive,entry['size'],entry['checksum'].removeprefix('md5:'),progress=progress,deadline=deadline)
  state.update(status='extracting',archive=proof,downloaded_bytes=proof['bytes']);save(record,state)
  state['members']=retain_members(archive,folder/(env+'-selected'));state.update(status='verified',completed_at_kst=now(),license='CC-BY-NC-SA-4.0',scope='original testbed evidence and provider line labels, not expert-certified derived response')
  save(record,state);archive.unlink();state['temporary_archive_removed']=not archive.exists();save(record,state)
 except BaseException as e:state.update(status='failed',error_type=type(e).__name__,error=str(e)[:200],updated_at_kst=now());save(record,state);raise
 return state

def acquire_range(folder,entry):
 env=entry['key'].removesuffix('.zip');record=folder/(env+'-range-acquisition.json')
 if record.exists():raise ValueError('Range acquisition evidence already exists')
 state={'environment':env,'status':'acquiring_selected_members','started_at_kst':now(),'source_url':entry['links']['self'],'published_whole_archive_checksum':entry['checksum'],'whole_archive_checksum_verified':False,'license':'CC-BY-NC-SA-4.0'};save(record,state)
 try:
  url=entry['links']['self']
  if not re.fullmatch(r'https://zenodo.org/api/records/5789064/files/[a-z]+\.zip/content',url):raise ValueError('Unexpected institutional source URL')
  source=RemoteZip(url,entry['size'],chunk=256*1024,max_transfer=32*1024*1024)
  state['members']=retain_members(source,folder/(env+'-range-selected'))
  # The provider does not expose ETag/Last-Modified on these file responses.
  # Re-read official record metadata; never invent an immutable HTTP validator.
  with request.urlopen(request.Request('https://zenodo.org/api/records/5789064',headers={'User-Agent':'SOC-research-provenance/1.0'}),timeout=45) as r:
   raw=r.read(2*1024*1024+1)
  if len(raw)>2*1024*1024:raise ValueError('Metadata response too large')
  latest=json.loads(raw);current=next(x for x in latest['files'] if x['key']==entry['key'])
  if (current['size'],current['checksum'],latest['metadata']['license']['id'])!=(entry['size'],entry['checksum'],'cc-by-nc-sa-4.0'):
   raise ValueError('Institutional source metadata changed')
  state.update(status='verified_selected_members',completed_at_kst=now(),transferred_bytes=source.transferred,requested_bytes_upper_bound=source.requested_bytes,range_requests=source.calls,etag=source.etag,last_modified=source.last_modified,record_metadata_rechecked=True,integrity_scope='TLS official versioned record URL + selected ZIP CRC and local SHA256; full published archive MD5 not computed',provider_labels_scope='testbed rule-generated line labels, not independent expert labels or real production incident proof')
 except BaseException as e:state.update(status='failed',error_type=type(e).__name__,error=str(e)[:200]);save(record,state);raise
 save(record,state);return state

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--folder',type=Path,required=True);p.add_argument('--method',choices=['range','full'],default='range');p.add_argument('--environment',choices=['russellmitchell','wheeler','wilson'],action='append');args=p.parse_args();folder=args.folder.resolve()
 if not (folder/'ait-lds-v2-record.json').is_file():raise ValueError('Acquire official metadata first')
 metadata=json.loads((folder/'ait-lds-v2-record.json').read_text());assert metadata['id']==5789064 and metadata['metadata']['license']['id']=='cc-by-nc-sa-4.0'
 environments=args.environment or ['russellmitchell','wheeler','wilson']
 if len(environments)!=len(set(environments)):raise ValueError('Duplicate environment')
 entries=[next(x for x in metadata['files'] if x['key']==env+'.zip') for env in environments]
 suffix='-acquisition.json' if args.method=='full' else '-range-acquisition.json'
 if any((folder/(x['key'].removesuffix('.zip')+suffix)).exists() for x in entries):raise ValueError('Existing acquisition evidence; no automatic overwrite or retry')
 budget=sum(x['size'] for x in entries) if args.method=='full' else 96*1024*1024
 if shutil.disk_usage(folder).free<budget+10*2**30:raise ValueError('Insufficient bounded acquisition space')
 os.nice(15)
 with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(lambda e:(acquire_environment if args.method=='full' else acquire_range)(folder,e),entries))
 save(folder/('ait-selected-acquisition-'+args.method+'.json'),{'at_kst':now(),'status':'completed','method':args.method,'environments':results,'license':'CC-BY-NC-SA-4.0','intended_use':'noncommercial capstone research; keep attribution and same-license conditions; no data/model publication by this command','gpu_or_service_actions':False})
 print(json.dumps({'status':'completed','environments':len(results),'retained_members':sum(len(r['members']) for r in results)}))
if __name__=='__main__':main()
