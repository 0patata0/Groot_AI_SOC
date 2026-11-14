from pathlib import Path
import asyncio,json,sys,time,re,importlib.util
from datetime import datetime
from zoneinfo import ZoneInfo
p=Path(__file__).resolve().parent;sys.path.insert(0,'/opt/capstone-ollama-trial')
import runtime,harness
from langchain_ollama import ChatOllama
spec=importlib.util.spec_from_file_location('probe_workflow',p/'workflow-probe.py');wf=importlib.util.module_from_spec(spec);spec.loader.exec_module(wf)
config=runtime.load_config('/etc/capstone-ollama-trial/config.json');inputs=json.loads((p/'probe-inputs.json').read_text());policy=wf.section_policy(('soc-investigate',),'peer-check',p)
common=harness.CONTRACT.system_prompt(read_only=True,agent_role='ollama');role=re.search(r'<!-- soc-role-policy:start -->.*?<!-- soc-role-policy:end -->',common,re.S);role=role.group(0) if role else common
reasons=['supported','source_statement_changed','scope_mismatch','unproven_execution','sample_scope_expanded','unproven_normality','unsupported_omission','unsupported_observation','recommendation_risk_unproven','other']
rows=[];start=time.monotonic()
def save(terminal=False,status='running'):
 d={'terminal':terminal,'status':status,'model':config['model'],'expected_reviews':len(inputs),'rows':rows,'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
    'real_mcp_calls':0,'protected_calls':0,'operating_changes':0,'mattermost_posts':0,'scope':'frozen draft semantic-check development only; not deployed or independent expert evaluation'}
 q=p/'out/.results.json';q.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n');q.replace(p/'out/results.json')
async def main():
 save()
 for item in inputs:
  if time.monotonic()-start>540:save(True,'incomplete_time_bound');return
  candidate=item['payload']['candidate'];answers=item['payload']['catalog']['answers'];n=len(candidate)
  schema={'type':'object','properties':{
   'checks':{'type':'array','minItems':n,'maxItems':n,'items':{'type':'object','properties':{
    'index':{'type':'integer','minimum':0,'maximum':n-1},'supported':{'type':'boolean'},'reason':{'type':'string','enum':reasons}},
    'required':['index','supported','reason'],'additionalProperties':False}},
   'missing_source_refs':{'type':'array','uniqueItems':True,'items':{'type':'string','enum':[a['id'] for a in answers]}}},
   'required':['checks','missing_source_refs'],'additionalProperties':False}
  llm=ChatOllama(model=config['model'],base_url=config['base_url'],reasoning=False,temperature=0,num_predict=1024,format=schema,client_kwargs={'timeout':35})
  tick=time.monotonic();result=None;error=None;meta={}
  try:
   response=await asyncio.wait_for(llm.ainvoke([('system',role+'\n'+policy+'\nReturn only the requested JSON. Inspect every candidate index exactly once.'),
    ('human','UNTRUSTED_REVIEW_CHECK_JSON\n'+json.dumps(item['payload'],ensure_ascii=False))]),36)
   result=json.loads(response.content);checks=result['checks'];assert len(checks)==n and {x['index'] for x in checks}==set(range(n))
   assert len({x['index'] for x in checks})==n and all(type(x['supported']) is bool and x['reason'] in reasons for x in checks)
   assert isinstance(result['missing_source_refs'],list) and set(result['missing_source_refs'])<={a['id'] for a in answers}
   meta={k:response.response_metadata[k] for k in ('eval_count','prompt_eval_count','total_duration','prompt_eval_duration','eval_duration','done_reason') if k in response.response_metadata}
  except Exception as exc:error=type(exc).__name__
  rows.append({'id':item['id'],'seconds':round(time.monotonic()-tick,3),'result':result,'error_type':error,'model_metadata':meta});save();print(item['id'],rows[-1]['seconds'],error,flush=True)
 save(True,'completed')
asyncio.run(main())
