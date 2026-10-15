#!/bin/bash
# Existing closed B batches and canary safety configuration only. No event input.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C TZ=Asia/Seoul
[[ $EUID == 0 && $# == 0 && $(cat /etc/machine-id) == 1e143067c98a44ffba6eaa925dc038d7 ]] || exit 64
stage=$(mktemp -d /var/tmp/capstone-history-analysis-preflight.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
/usr/local/bin/docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/ossec.conf > "$stage/ossec.conf"
python3 -B - "$stage/ossec.conf" <<'PY'
import ast,datetime,hashlib,json,pathlib,re,stat,sys,xml.etree.ElementTree as ET
batches=[
 ('67f858b9c78551e3ca95cd3bc9948cf9ded19834d1e0d9d9f78b4bb4c95fd33a','4f3fd39e4bd0e63eca07e00e5dac4515f59b473a401c97e84ed206d568f1128d','067728c72a202e44c7244a29b3c403a6ca7533587d4ad18d1d11984f8d531ec3',1000),
 ('bf58e25ad123f6d84c54b66ced22e186750c2328f67d59439b1bccb4c47fae68','5e96e0e71bb8c67bf5e751c5d71fca467d26058440229503fe45c8036e70fe58','18c79f4f8473da11bd7edf5e6f472e22aeb4d43c5fb2dcc5e08117ea87f4e697',481)]
result=[]
pattern=re.compile(r'^(AGENT_BLOCK|FW_DROP_IN|FW_DROP_OUT|FW_DROP_FWD|FW_SHADOW_OUT|FW_SSH_RATE|SPOOF)\s')
for bid,psha,msha,count in batches:
 p=pathlib.Path('/var/lib/capstone-history-receipts/batches')/bid
 assert p.is_dir() and not p.is_symlink() and p.stat().st_uid==0 and stat.S_IMODE(p.stat().st_mode)==0o700
 values=[]
 for name,wanted,limit in [('kernel.jsonl',psha,33554432),('manifest.json',msha,65536)]:
  f=p/name;t=f.lstat();assert stat.S_ISREG(t.st_mode) and t.st_uid==0 and t.st_nlink==1 and stat.S_IMODE(t.st_mode)==0o400 and 0<t.st_size<=limit
  data=f.read_bytes();assert hashlib.sha256(data).hexdigest()==wanted;values.append(data)
 rows=[json.loads(line) for line in values[0].splitlines()]
 assert len(rows)==count and all(r['_TRANSPORT']=='kernel' for r in rows)
 strings=sum(isinstance(r.get('MESSAGE'),str) for r in rows)
 selected=sum(isinstance(r.get('MESSAGE'),str) and pattern.match(r['MESSAGE']) is not None for r in rows)
 result.append({'batch_id':bid,'records':len(rows),'message_strings':strings,'nft_selector_candidates':selected,'non_target_kernel_records':len(rows)-selected,'payload_sha_verified':True,'manifest_sha_verified':True})
xml=ET.fromstring('<root>'+pathlib.Path(sys.argv[1]).read_text()+'</root>')
active=len(xml.findall('.//active-response')); integrations=len(xml.findall('.//integration'))
assert active==0 and integrations==0
rules=pathlib.Path('/var/lib/docker/volumes/single-node_wazuh_etc/_data/rules/capstone_vector_rules.xml')
parsed=ET.fromstring('<root>'+rules.read_text()+'</root>')
for ruleid in ('100293','100294'):
 rule=parsed.find(f'.//rule[@id="{ruleid}"]');assert rule is not None and rule.attrib['level']=='3'
 opts=[n.text for n in rule.findall('options')];assert 'no_email_alert' in opts and 'no_full_log' in opts
bot=pathlib.Path('/opt/socbot/soc_bot.py');tree=ast.parse(bot.read_text());funcs={f.name:f for f in tree.body if isinstance(f,ast.FunctionDef)}
def default(name,param):
 f=funcs[name];mapping=dict(zip([x.arg for x in f.args.args][-len(f.args.defaults):],f.args.defaults));v=mapping[param];assert isinstance(v,ast.Constant) and type(v.value) is int;return v.value
def minimum_call(caller,callee):
 vals=[]
 for n in ast.walk(funcs[caller]):
  if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id==callee:
   v=next((kw.value for kw in n.keywords if kw.arg=='min_level'),None)
   if v is None: vals.append(default(callee,'min_level'))
   else: assert isinstance(v,ast.Constant) and type(v.value) is int;vals.append(v.value)
 assert vals
 return min(vals)
report=minimum_call('build_report','recent_alerts')
summary=minimum_call('build_summary','agg_alerts')
monitor=default('recent_fingerprint','min_level')
assert min(report,summary,monitor)>=5
print(json.dumps({'checked_at_kst':datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).isoformat(timespec='seconds'),'kind':'B_preserved_batch_and_canary_readonly_preflight','batches':result,'total_records':sum(x['records'] for x in result),'total_nft_selector_candidates':sum(x['nft_selector_candidates'] for x in result),'wazuh_active_response_blocks':active,'wazuh_integration_blocks':integrations,'log_alert_level':[x.text for x in xml.findall('.//alerts/log_alert_level')],'email_alert_level':[x.text for x in xml.findall('.//alerts/email_alert_level')],'canary_rule_ids':['100293','100294'],'canary_level':3,'canary_no_email_and_no_full_log':True,'soc_report_min_level':report,'soc_summary_min_level':summary,'soc_monitor_default_min_level':monitor,'soc_bot_source_sha256':hashlib.sha256(bot.read_bytes()).hexdigest(),'vector_rules_sha256':hashlib.sha256(rules.read_bytes()).hexdigest(),'operational_input_written':False,'indexer_write':False,'raw_or_cursor_exported':False},ensure_ascii=False))
PY
