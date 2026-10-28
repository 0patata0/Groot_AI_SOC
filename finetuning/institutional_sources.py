"""Snapshot official role/incident reference metadata without packages or GPUs."""
import argparse,hashlib,json,re
from pathlib import Path
from urllib import request
from datetime import datetime,timezone,timedelta
SOURCES=[('nice-components-v2.2.0.json','https://csrc.nist.gov/csrc/media/Projects/cprt/documents/nice/v2-2-0_nf_components.json',8*1024*1024),('enisa-ecsf-role-profiles-2022.pdf','https://www.enisa.europa.eu/sites/default/files/publications/European%20Cybersecurity%20Skills%20Framework%20Role%20Profiles.pdf',8*1024*1024),('ait-lds-v2-record.json','https://zenodo.org/api/records/5789064',2*1024*1024)]
ROLES=('PD-WRL-001','PD-WRL-003','PD-WRL-007')
def now():return datetime.now(timezone(timedelta(hours=9))).isoformat()
def fetch(url,limit):
 req=request.Request(url,headers={'User-Agent':'SOC-research-provenance/1.0','Accept-Encoding':'identity'})
 with request.urlopen(req,timeout=45) as response:
  data=response.read(limit+1);final=response.url
 if len(data)>limit:raise ValueError('Institutional response exceeds bound')
 return data,final

def role_tasks(document):
 if not any(d.get('version')=='2.2.0' for d in document['documents']):raise ValueError('Wrong NICE version')
 elements={e['element_identifier']:e for e in document['elements']};rows=[]
 for identifier in ROLES:
  role=elements[identifier]
  if role['element_type']!='work_role':raise ValueError('Invalid work role')
  tasks={}
  for relation in document['relationships']:
   source=relation['source_element_identifier'];dest=relation['dest_element_identifier']
   other=dest if source==identifier else source if dest==identifier else None
   element=elements.get(other,{})
   if element.get('element_type')=='task':tasks[other]=element
  if not tasks:raise ValueError('No tasks bound to role')
  rows.append({'role':role,'tasks':list(tasks.values())})
 return rows

def collect_metadata(folder):
 if folder.exists():raise ValueError('Use a new snapshot folder')
 folder.mkdir(parents=True);receipts=[]
 for name,url,bound in SOURCES:
  data,final=fetch(url,bound)
  if name.endswith('.json'):json.loads(data)
  elif not data.startswith(b'%PDF-'):raise ValueError('Not an institutional PDF')
  (folder/name).write_bytes(data);receipts.append({'name':name,'source_url':url,'final_url':final,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
 document=json.loads((folder/'nice-components-v2.2.0.json').read_text());roles=role_tasks(document)
 (folder/'nice-selected-roles.json').write_text(json.dumps({'document':document['documents'],'roles':roles},ensure_ascii=False,indent=2)+'\n')
 record={'at_kst':now(),'sources':receipts,'role_task_memberships':{r['role']['element_identifier']:len(r['tasks']) for r in roles},'no_large_dataset_archive_downloaded':True}
 (folder/'acquisition-manifest.json').write_text(json.dumps(record,indent=2)+'\n');return record

def collect_kev(folder,revision):
 if not re.fullmatch('[0-9a-f]{40}',revision):raise ValueError('Pin the official repository full commit SHA')
 if folder.exists():raise ValueError('Use a new KEV snapshot folder')
 folder.mkdir(parents=True);files=[]
 for name in ('LICENSE','README.md','known_exploited_vulnerabilities.json','known_exploited_vulnerabilities_schema.json'):
  url='https://raw.githubusercontent.com/cisagov/kev-data/'+revision+'/'+name;data,final=fetch(url,8*1024*1024);(folder/name).write_bytes(data);files.append({'name':name,'source_url':url,'final_url':final,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
 if 'Creative Commons 0 1.0 License' not in (folder/'LICENSE').read_text():raise ValueError('KEV license changed')
 value=json.loads((folder/'known_exploited_vulnerabilities.json').read_text());rows=value['vulnerabilities']
 if len(rows)!=value['count'] or len({r['cveID'] for r in rows})!=len(rows):raise ValueError('KEV count/identity mismatch')
 record={'at_kst':now(),'source':'https://github.com/cisagov/kev-data','commit':revision,'files':files,'license':'CC0-1.0','records':len(rows),'catalog_version':value['catalogVersion'],'released_at_kst':datetime.fromisoformat(value['dateReleased'].replace('Z','+00:00')).astimezone(timezone(timedelta(hours=9))).isoformat(),'scope':'reference for triage; not a finding about any local host'}
 (folder/'acquisition-manifest.json').write_text(json.dumps(record,indent=2)+'\n');return record

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=['metadata','kev']);p.add_argument('--folder',type=Path,required=True);p.add_argument('--revision');a=p.parse_args()
 if a.mode=='kev' and not a.revision:raise ValueError('Explicit KEV commit required')
 print(json.dumps(collect_metadata(a.folder) if a.mode=='metadata' else collect_kev(a.folder,a.revision),ensure_ascii=False))
if __name__=='__main__':main()
