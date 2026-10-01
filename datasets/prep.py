#!/usr/bin/env python3
"""datasets/prep.py — 파인튜닝 전처리(재현 가능). raw/ → processed/ (gitignore). 외부 패키지 불필요(stdlib).
스테이지: hermes | glaive2 | traces | sevenllm | attacklm | salad | ait | eval | knowledge  (--stages 로 선택, 기본 전부)
  hermes    hermes-fc-v1 5파일 dedupe + 미정의 툴 제거                 → hermes_fc_v1.dedup.jsonl
  glaive2   glaive-fc-v2 문자열 → ShareGPT/Hermes(<tool_call>) 변환, 내부+hermes 대비 dedupe → glaive_fc_v2.hermes.jsonl
  traces    Hermes 하네스 트레이스 검증·정규화(툴콜 유효성, 플레이스홀더 제외) → hermes_agent_traces.jsonl
  sevenllm  SEVENLLM train: dedupe + lang 태그, 영어 서브셋                 → sevenllm_en.jsonl (+ sevenllm_all.jsonl)
  attacklm  AttackLM 원천 버킷만(balanced 파생본 제외) dedupe + 라이선스 보존 → attacklm.jsonl, attacklm.permissive.jsonl
  salad     val/train 균형(악성 전부 + 양성 층화 다운샘플, 스트리밍)         → salad_{val,train}.balanced.csv (test 는 평가 전용, 미처리)
  ait       AIT-ADS phase_window 라벨 + 환경 단위 split + 단계 상한          → ait/<env>.labeled.jsonl, ait/split.json
  eval      평가셋 통일 스키마(학습 금지)                                   → eval/*.jsonl
  knowledge 룰·지식 JSONL(Wazuh/ET Open/CRS/Sigma/Atomic/ATT&CK/KEV)       → knowledge/*.jsonl
"""
import argparse, csv, hashlib, io, json, os, random, re, zipfile, tarfile, collections, datetime, glob, sys
ap=argparse.ArgumentParser()
ap.add_argument('--stages',default='all'); ap.add_argument('--seed',type=int,default=42); ap.add_argument('--benign-ratio',type=float,default=1.0)
ap.add_argument('--ait-normal-cap',type=int,default=20000); ap.add_argument('--ait-phase-cap',type=int,default=5000); ap.add_argument('--ait-window-pad',type=float,default=0.0)
ap.add_argument('--ait-val',default='wheeler'); ap.add_argument('--ait-holdout',default='wilson')
A=ap.parse_args(); ST=set(A.stages.split(',')) if A.stages!='all' else {'hermes','glaive2','traces','sevenllm','attacklm','salad','ait','eval','knowledge'}
R='datasets/raw'; O='datasets/processed'
for d in ['', 'ait','eval','knowledge']: os.makedirs(f'{O}/{d}',exist_ok=True)
random.seed(A.seed); stats=json.load(open(f'{O}/STATS.json'))['stats'] if os.path.exists(f'{O}/STATS.json') else {}
TC=re.compile(r'<tool_call>\s*(\{.*?\})\s*</tool_call>', re.S); CJK=re.compile(r'[一-鿿]'); HANG=re.compile(r'[가-힣]')
def H(x): return hashlib.sha1(json.dumps(x,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
def wjsonl(path,rows):
    with open(path,'w',encoding='utf-8') as w:
        for r in rows: w.write(json.dumps(r,ensure_ascii=False)+'\n')
def tool_names(tools):
    names=set()
    try:
        tl=json.loads(tools) if isinstance(tools,str) else tools
        for t in tl or []: names.add((t.get('function') or t).get('name'))
    except Exception: pass
    return names
def bad_calls(conv,names):
    """gpt 턴의 <tool_call> 중 JSON 불량/미정의 툴 수 (system 턴의 형식 예시는 제외)"""
    bad=0; n=0
    for c in conv:
        if c.get('from')!='gpt': continue
        for m in TC.findall(c.get('value','')):
            n+=1
            try: o=json.loads(m)
            except Exception: bad+=1; continue
            if names and o.get('name') not in names: bad+=1
    return n,bad
HERMES_SYS=("You are a function calling AI model. You are provided with function signatures within <tools> </tools> XML tags. "
            "You may call one or more functions to assist with the user query. Don't make assumptions about what values to plug into functions.\n<tools>\n{tools}\n</tools>\n"
            "For each function call return a json object with function name and arguments within <tool_call> </tool_call> tags with the following schema:\n"
            "<tool_call>\n{{'arguments': <args-dict>, 'name': <function-name>}}\n</tool_call>")

# ---------- hermes ----------
hermes_keys=set()
if 'hermes' in ST or os.path.exists(f'{O}/hermes_fc_v1.dedup.jsonl'):
    if 'hermes' in ST:
        files=['func-calling-singleturn.json','func-calling.json','glaive-function-calling-5k.json','json-mode-agentic.json','json-mode-singleturn.json']
        out=[]; dup=unknown=total=0
        for f in files:
            for s in json.load(open(f'{R}/hermes-function-calling-v1/{f}')):
                total+=1; k=H(s.get('conversations'))
                if k in hermes_keys: dup+=1; continue
                n,b=bad_calls(s.get('conversations',[]),tool_names(s.get('tools')))
                if b: unknown+=1; continue
                hermes_keys.add(k); s['_source_file']=f; out.append(s)
        wjsonl(f'{O}/hermes_fc_v1.dedup.jsonl',out)
        stats['hermes']={'input':total,'duplicates_removed':dup,'unknown_tool_removed':unknown,'output':len(out)}
        print(f"[hermes] {total} → dedupe -{dup}, 미정의툴 -{unknown} → {len(out)}")
    else:
        for l in open(f'{O}/hermes_fc_v1.dedup.jsonl',encoding='utf-8'): hermes_keys.add(H(json.loads(l).get('conversations')))
# 형식이 다른 세트 간 중복 판정 키: 모든 사용자 발화 + 툴콜 객체(정규화) — 첫 발화만 쓰면 템플릿 오프닝 때문에 과잉 제거됨
def conv_key(conv,tools=None):
    """사용자 발화 + 툴콜 객체 + 사용 가능한 툴 이름. 툴 이름을 넣지 않으면 '예약해줘' 류 거절 템플릿이 툴 맥락 무시하고 과잉 병합됨(실측 3,847/그룹)"""
    users=[(t.get('value') or '').strip() for t in conv if t.get('from') in ('human','user')]
    calls=[]
    for t in conv:
        if t.get('from') in ('gpt','assistant'):
            for m in TC.findall(t.get('value','')):
                try: calls.append(json.dumps(json.loads(m),sort_keys=True,ensure_ascii=False))
                except Exception: calls.append(m.strip())
    return H({'u':users,'c':calls,'t':sorted(tool_names(tools)) if tools else []})
hermes_conv_keys=set()
if os.path.exists(f'{O}/hermes_fc_v1.dedup.jsonl'):
    for l in open(f'{O}/hermes_fc_v1.dedup.jsonl',encoding='utf-8'):
        o=json.loads(l); hermes_conv_keys.add(conv_key(o.get('conversations',[]),o.get('tools')))

# ---------- glaive2 ----------
if 'glaive2' in ST:
    FC=re.compile(r'<functioncall>\s*(\{.*?\})\s*(?:<\|endoftext\|>|$)', re.S)
    ARG=re.compile(r'"arguments"\s*:\s*\'(.*)\'\s*\}\s*$', re.S)
    g=json.load(open(f'{R}/glaive-fc-v2/glaive-function-calling-v2.json'))
    out=[]; chat_only=[]; seen=set(); dup_in=dup_h=parse_fail=notools=0
    for s in g:
        sysr=s.get('system','') or ''; chat=s.get('chat','') or ''
        # tools: SYSTEM 문자열에서 JSON 객체들 추출
        tools=[]; i=sysr.find('{')
        dec=json.JSONDecoder()
        while i!=-1 and i<len(sysr):
            try: obj,end=dec.raw_decode(sysr[i:]); tools.append(obj); i=sysr.find('{',i+end)
            except Exception: i=sysr.find('{',i+1)
        if not tools: notools+=1
        # 턴 분리
        parts=re.split(r'(USER:|ASSISTANT:|FUNCTION RESPONSE:)', chat)
        conv=[]; ok=True
        if tools:
            conv.append({'from':'system','value':HERMES_SYS.format(tools=json.dumps([{'type':'function','function':t} for t in tools],ensure_ascii=False))})
        else:
            conv.append({'from':'system','value':'You are a helpful assistant.'})
        j=1
        while j<len(parts)-1:
            mk=parts[j]; txt=parts[j+1].replace('<|endoftext|>','').strip(); j+=2
            if mk=='USER:': conv.append({'from':'human','value':txt})
            elif mk=='FUNCTION RESPONSE:': conv.append({'from':'tool','value':f'<tool_response>\n{txt}\n</tool_response>'})
            else:
                m=FC.search(txt)
                if m:
                    raw=m.group(1); name=re.search(r'"name"\s*:\s*"([^"]+)"',raw); am=ARG.search(raw); args=None
                    if am:
                        try: args=json.loads(am.group(1))
                        except Exception:
                            try: args=json.loads(am.group(1).replace("\\'","'"))
                            except Exception: args=am.group(1)
                    if not name: ok=False; break
                    call={'name':name.group(1),'arguments':args if args is not None else {}}
                    pre=txt[:m.start()].strip()
                    conv.append({'from':'gpt','value':(pre+'\n' if pre else '')+'<tool_call>\n'+json.dumps(call,ensure_ascii=False)+'\n</tool_call>'})
                else: conv.append({'from':'gpt','value':txt})
        if not ok or len(conv)<3: parse_fail+=1; continue
        k=conv_key(conv,[{'type':'function','function':t} for t in tools] if tools else None)
        if k in seen: dup_in+=1; continue
        if k in hermes_conv_keys: dup_h+=1; continue
        seen.add(k); rec={'id':f'glaive2-{len(out)+len(chat_only)}','conversations':conv,'tools':json.dumps([{'type':'function','function':t} for t in tools],ensure_ascii=False) if tools else None,'_source':'glaiveai/glaive-function-calling-v2'}
        (out if tools else chat_only).append(rec)   # 툴 없는 일반 잡담은 별도 파일(툴콜 학습 목적엔 제외)
    wjsonl(f'{O}/glaive_fc_v2.hermes.jsonl',out); wjsonl(f'{O}/glaive_fc_v2.chat_only.jsonl',chat_only)
    stats['glaive2']={'input':len(g),'parse_fail':parse_fail,'dup_internal':dup_in,'dup_vs_hermes':dup_h,'output_with_tools':len(out),'chat_only':len(chat_only)}
    print(f"[glaive2] {len(g)} → 변환실패 -{parse_fail}, 내부중복 -{dup_in}, hermes중복 -{dup_h} → 툴콜 {len(out)} / 잡담 {len(chat_only)}(별도)")

# ---------- traces ----------
if 'traces' in ST:
    out=[]; n=bad=unk=dup=0; calls=0
    for l in open(f'{R}/hermes-agent-traces-filtered/train.jsonl',encoding='utf-8'):
        n+=1; s=json.loads(l); conv=s.get('conversations',[])
        k=H(conv)
        if k in hermes_keys: dup+=1; continue
        c,b=bad_calls(conv,tool_names(s.get('tools'))); calls+=c
        if b: unk+=1; continue
        s['_source']='DJLougen/hermes-agent-traces-filtered'; out.append(s)
    wjsonl(f'{O}/hermes_agent_traces.jsonl',out)
    stats['traces']={'input':n,'bad_tool_removed':unk,'dup_vs_hermes':dup,'output':len(out),'assistant_tool_calls':calls}
    print(f"[traces] {n} → 불량툴콜 -{unk}, 중복 -{dup} → {len(out)} (assistant 툴콜 {calls})")

# ---------- sevenllm ----------
if 'sevenllm' in ST:
    seen=set(); allr=[]; en=[]; dup=0; cat=collections.Counter(); lang=collections.Counter()
    for l in open(f'{R}/sevenllm/train.jsonl',encoding='utf-8'):
        o=json.loads(l); k=H([o.get('instruction'),o.get('input'),o.get('output')])
        if k in seen: dup+=1; continue
        seen.add(k); txt=' '.join(str(o.get(f,'')) for f in ('instruction','input','output','thought'))
        o['lang']='zh' if CJK.search(txt) else ('ko' if HANG.search(txt) else 'en'); lang[o['lang']]+=1; cat[o.get('category')]+=1
        o['_source']='Multilingual-Multimodal-NLP/SEVENLLM-Dataset'; allr.append(o)
        if o['lang']=='en': en.append(o)
    wjsonl(f'{O}/sevenllm_all.jsonl',allr); wjsonl(f'{O}/sevenllm_en.jsonl',en)
    stats['sevenllm']={'input':len(allr)+dup,'dup':dup,'all':len(allr),'en':len(en),'lang':dict(lang),'categories':len(cat),'top_categories':cat.most_common(5)}
    print(f"[sevenllm] {len(allr)+dup} → dedupe -{dup} → all {len(allr)} / en {len(en)} | lang {dict(lang)}")

# ---------- attacklm ----------
if 'attacklm' in ST:
    zf=zipfile.ZipFile(f'{R}/attacklm/attacklm-dataset-main.zip'); seen=set(); out=[]; dup=0; lic=collections.Counter(); src=collections.Counter()
    for nme in zf.namelist():
        if '/data/datasets/buckets/sources/' in nme and nme.endswith('.jsonl'):
            for l in zf.read(nme).decode('utf-8','ignore').splitlines():
                if not l.strip(): continue
                o=json.loads(l); k=H(o.get('messages'))
                if k in seen: dup+=1; continue
                seen.add(k); o['_bucket']=nme.split('/sources/',1)[1].rsplit('/',1)[0]; lic[o.get('license')]+=1; src[o.get('source')]+=1; out.append(o)
    PERM=('MIT','Apache','BSD','CC-BY-4','CC0','CC BY 4','Unlicense','DRL','ISC','Public')
    perm=[o for o in out if any(p.lower() in str(o.get('license','')).lower() for p in PERM)]
    wjsonl(f'{O}/attacklm.jsonl',out); wjsonl(f'{O}/attacklm.permissive.jsonl',perm)
    stats['attacklm']={'output':len(out),'dup':dup,'permissive':len(perm),'licenses':dict(lic),'sources':dict(src)}
    print(f"[attacklm] 원천버킷 {len(out)}(중복 -{dup}) | 관대 라이선스 {len(perm)} | 라이선스 {dict(lic)}")

# ---------- salad ----------
def balance_csv(src,dst,ratio):
    """2-pass 스트리밍: 악성 전부 + 양성 source_dataset 층화 reservoir"""
    r=csv.reader(open(src,encoding='utf-8',errors='ignore')); h=next(r); ix={c:i for i,c in enumerate(h)}
    M=0; B=collections.Counter()
    for row in r:
        if len(row)!=len(h): continue
        if row[ix['is_malicious']]=='True': M+=1
        else: B[row[ix['source_dataset']]]+=1
    tgt={s:round(M*ratio*c/sum(B.values())) for s,c in B.items()}
    res={s:[] for s in B}; seen=collections.Counter(); tri=collections.Counter(); n=0
    r=csv.reader(open(src,encoding='utf-8',errors='ignore')); next(r)
    with open(dst,'w',encoding='utf-8',newline='') as w:
        wr=csv.writer(w); wr.writerow(h)
        for row in r:
            if len(row)!=len(h): continue
            if row[ix['is_malicious']]=='True': wr.writerow(row); tri[row[ix['triage_decision']]]+=1; n+=1
            else:
                s=row[ix['source_dataset']]; seen[s]+=1; cap=tgt[s]
                if len(res[s])<cap: res[s].append(row)
                else:
                    j=random.randint(0,seen[s]-1)
                    if j<cap: res[s][j]=row
        for s,lst in res.items():
            for row in lst: wr.writerow(row); tri[row[ix['triage_decision']]]+=1; n+=1
    return {'malicious':M,'benign_in':sum(B.values()),'benign_kept':sum(len(v) for v in res.values()),'output':n,'triage':dict(tri)}
if 'salad' in ST:
    for sp in ['val','train']:
        st=balance_csv(f'{R}/salad-soc/salad_{sp}.csv',f'{O}/salad_{sp}.balanced.csv',A.benign_ratio); stats[f'salad_{sp}']=st
        print(f"[salad {sp}] 악성 {st['malicious']} + 양성 {st['benign_kept']}/{st['benign_in']} = {st['output']} | triage {st['triage']}")
    stats['salad_test']={'note':'평가 전용 — 미처리(raw/salad-soc/salad_test.csv)'}

# ---------- ait ----------
if 'ait' in ST:
    zf=zipfile.ZipFile(f'{R}/ait-ads/ait_ads.zip'); lab=collections.defaultdict(list)
    for r in csv.DictReader(open(f'{R}/ait-ads/labels.csv')): lab[r['scenario']].append((r['attack'],float(r['start']),float(r['end'])))
    envs=sorted(lab); split={'train':[e for e in envs if e not in (A.ait_val,A.ait_holdout)],'val':[A.ait_val],'holdout':[A.ait_holdout]}
    json.dump(split,open(f'{O}/ait/split.json','w'),indent=1)
    def ts(o):
        try: return datetime.datetime.fromisoformat((o.get('@timestamp') or '').replace('Z','+00:00')).timestamp()
        except Exception: return None
    aits={}
    for env in envs:
        wins=lab[env]; n=keep=normal_seen=hi=bad_ts=0; res=[]; pres=collections.defaultdict(list); pseen=collections.Counter(); pc=collections.Counter()
        with zf.open(f'{env}_wazuh.json') as fh, open(f'{O}/ait/{env}.labeled.jsonl','w',encoding='utf-8') as w:
            for line in io.TextIOWrapper(fh,encoding='utf-8',errors='ignore'):
                line=line.strip()
                if not line: continue
                n+=1
                try: o=json.loads(line)
                except Exception: continue
                e=ts(o)
                if e is None: bad_ts+=1; continue
                phase=next((a for a,s,t in wins if s-A.ait_window_pad<=e<=t+A.ait_window_pad),None); o['ait_env']=env
                if phase:
                    o['phase_window']=phase; pc[phase]+=1; keep+=1; hi+=((o.get('rule') or {}).get('level',0)>=10); pseen[phase]+=1; lst=pres[phase]
                    if len(lst)<A.ait_phase_cap: lst.append(o)
                    else:
                        j=random.randint(0,pseen[phase]-1)
                        if j<A.ait_phase_cap: lst[j]=o
                else:
                    normal_seen+=1; o['phase_window']='normal'
                    if len(res)<A.ait_normal_cap: res.append(o)
                    else:
                        j=random.randint(0,normal_seen-1)
                        if j<A.ait_normal_cap: res[j]=o
            kept={p:len(l) for p,l in pres.items()}
            for p,l in pres.items():
                for o in l: w.write(json.dumps(o,ensure_ascii=False)+'\n')
            for o in res: w.write(json.dumps(o,ensure_ascii=False)+'\n')
        role='train' if env in split['train'] else ('val' if env in split['val'] else 'holdout')
        aits[env]={'split':role,'alerts':n,'bad_ts':bad_ts,'attack_window':keep,'attack_level10plus':hi,'normal_seen':normal_seen,'normal_kept':len(res),'phases_in_window':dict(pc),'phases_kept':kept,'file_MB':round(os.path.getsize(f'{O}/ait/{env}.labeled.jsonl')/1e6,1)}
        print(f"[ait] {env:16} {role:7} alerts={n:8} window={keep:7} → kept {sum(kept.values()):6} + normal {len(res)} → {aits[env]['file_MB']}MB")
    stats['ait']={'split':split,'envs':aits,'note':'phase_window = labels.csv 시각 구간(구간 내 노이즈 포함, 단계 컨텍스트 라벨)'}

# ---------- eval ----------
if 'eval' in ST:
    ev={}
    rows=[]
    seenq={}
    for f in sorted(glob.glob(f'{R}/cybermetric/CyberMetric-*-v1.json'),key=lambda x:-os.path.getsize(x)):   # 10000 부터
        d=json.load(open(f)); qs=d.get('questions') or d; sub=os.path.basename(f)
        for q in qs:
            key=(q.get('question') or '').strip()
            if key in seenq: seenq[key]['subsets'].append(sub); continue
            seenq[key]={'source':'CyberMetric','subsets':[sub],'question':q.get('question'),'options':q.get('answers'),'answer':q.get('solution')}
    rows=list(seenq.values()); wjsonl(f'{O}/eval/cybermetric.jsonl',rows); ev['cybermetric']=len(rows)   # 2000/500/80 은 10000 의 부분집합 → 질문 기준 dedupe
    rows=[]; r=csv.reader(open(f'{R}/cti-bench/cti-mcq.tsv',encoding='utf-8'),delimiter='\t'); h=next(r)
    for row in r:
        d=dict(zip(h,row)); opts={k.split()[-1]:d[k] for k in h if k.startswith('Option')}
        rows.append({'source':'CTIBench-MCQ','question':d.get('Question'),'options':opts,'answer':d.get('GT') or d.get('Answer'),'url':d.get('URL')})
    wjsonl(f'{O}/eval/cti_mcq.jsonl',rows); ev['cti_mcq']=len(rows)
    for t in ['rcm','rcm-2021','vsp','ate','taa']:
        rows=[]; r=csv.reader(open(f'{R}/cti-bench/cti-{t}.tsv',encoding='utf-8'),delimiter='\t'); h=next(r)
        for row in r: d=dict(zip(h,row)); rows.append({'source':f'CTIBench-{t}','prompt':d.get('Prompt'),'description':d.get('Description') or d.get('Text'),'answer':d.get('GT'),'url':d.get('URL')})
        wjsonl(f'{O}/eval/cti_{t.replace("-","_")}.jsonl',rows); ev[f'cti_{t}']=len(rows)
    rows=[]
    for f in sorted(glob.glob(f'{R}/secqa/secqa_v*_test.csv')):
        r=csv.DictReader(open(f,encoding='utf-8'))
        for d in r:
            opts={k:d[k] for k in d if k in ('A','B','C','D')}
            rows.append({'source':'SecQA','subset':os.path.basename(f),'question':d.get('Question'),'options':opts,'answer':d.get('Answer')})
    wjsonl(f'{O}/eval/secqa.jsonl',rows); ev['secqa']=len(rows)
    zf=zipfile.ZipFile(f'{R}/attacklm/attacklm-dataset-main.zip'); q=[n for n in zf.namelist() if n.endswith('bench/questions.jsonl')]
    rows=[json.loads(l) for l in zf.read(q[0]).decode('utf-8').splitlines() if l.strip()] if q else []
    wjsonl(f'{O}/eval/attacklm_bench.jsonl',rows); ev['attacklm_bench']=len(rows)
    stats['eval']=ev; print(f"[eval] {ev} (학습 금지: CTIBench·SecQA 는 CC-BY-NC-SA)")

# ---------- knowledge ----------
if 'knowledge' in ST:
    kn={}
    # Wazuh rules (regex; 파일은 다중 루트라 XML 파서 불가)
    rows=[]
    for f in sorted(glob.glob(f'{R}/wazuh-ruleset/ruleset/rules/*.xml')):
        txt=open(f,encoding='utf-8',errors='ignore').read(); gname=re.search(r'<group name="([^"]+)"',txt)
        for m in re.finditer(r'<rule id="(\d+)" level="(\d+)"[^>]*>(.*?)</rule>',txt,re.S):
            b=m.group(3); d=re.search(r'<description>(.*?)</description>',b,re.S); g=re.search(r'<group>(.*?)</group>',b,re.S)
            rows.append({'rule_id':int(m.group(1)),'level':int(m.group(2)),'description':(d.group(1).strip() if d else ''),'groups':sorted(set(x.strip() for x in ((gname.group(1) if gname else '')+','+(g.group(1) if g else '')).split(',') if x.strip())),
                         'mitre':re.findall(r'<id>(T\d+(?:\.\d+)?)</id>',b),'if_sid':re.findall(r'<if_sid>([^<]+)</if_sid>',b),'if_group':re.findall(r'<if_group>([^<]+)</if_group>',b),'file':os.path.basename(f)})
    wjsonl(f'{O}/knowledge/wazuh_rules.jsonl',rows); kn['wazuh_rules']=len(rows)
    # ET Open
    rows=[]; tf=tarfile.open(f'{R}/et-open/emerging.rules.tar.gz')
    for m in tf.getmembers():
        if not m.name.endswith('.rules'): continue
        for l in tf.extractfile(m).read().decode('utf-8','ignore').splitlines():
            if not l.startswith('alert'): continue
            hdr=l.split('(',1)[0].split(); opts=l[l.find('(')+1:l.rfind(')')]
            kv=collections.defaultdict(list)
            for part in re.split(r';\s*(?=[a-z_]+:|[a-z_]+;)',opts):
                if ':' in part: k,v=part.split(':',1); kv[k.strip()].append(v.strip().strip('"'))
            md={}
            for x in kv.get('metadata',[]):
                for kv2 in x.split(','):
                    kv2=kv2.strip().split(' ',1)
                    if len(kv2)==2: md.setdefault(kv2[0],[]).append(kv2[1])
            rows.append({'sid':int(kv['sid'][0]) if kv.get('sid') else None,'msg':kv.get('msg',[''])[0],'classtype':kv.get('classtype',[''])[0],'proto':hdr[1] if len(hdr)>1 else '','src':' '.join(hdr[2:4]),'dst':' '.join(hdr[5:7]),'severity':md.get('signature_severity',[None])[0],'cve':md.get('cve',[]),'attack_target':md.get('attack_target',[None])[0],'reference':kv.get('reference',[]),'file':os.path.basename(m.name)})
    wjsonl(f'{O}/knowledge/et_open_rules.jsonl',rows); kn['et_open_rules']=len(rows)
    # CRS
    rows=[]; cz=zipfile.ZipFile(f'{R}/coreruleset/coreruleset-v4.29.0.zip')
    for n in cz.namelist():
        if not (n.endswith('.conf') and '/rules/' in n): continue
        txt=re.sub(r'\\\n\s*',' ',cz.read(n).decode('utf-8','ignore'))   # 백슬래시 줄바꿈 연속행 결합
        for line in txt.splitlines():
            line=line.strip()
            if not line.startswith('SecRule'): continue
            rid=re.search(r'\bid:(\d+)',line)
            if not rid: continue
            msg=re.search(r"msg:'((?:[^'\\]|\\.)*)'",line); sev=re.search(r"severity:'([A-Z]+)'",line); tags=re.findall(r"tag:'([^']+)'",line)
            parts=re.match(r'SecRule\s+(\S+)\s+"((?:[^"\\]|\\.)*)"',line)
            rows.append({'id':int(rid.group(1)),'msg':msg.group(1) if msg else '','severity':sev.group(1) if sev else None,'tags':tags,'paranoia_level':next((t.split('/')[-1] for t in tags if t.startswith('paranoia-level')),None),'attack':[t for t in tags if t.startswith('attack-')],'variables':(parts.group(1) if parts else '')[:200],'operator':(parts.group(2) if parts else '')[:200],'file':os.path.basename(n),'control':not msg})
    wjsonl(f'{O}/knowledge/crs_rules.jsonl',rows); kn['crs_rules']=len(rows); kn['crs_rules_with_msg']=sum(1 for r in rows if r['msg'])
    # Sigma (minimal line parser: 최상위 스칼라·description 블록·tags 리스트·logsource 하위)
    rows=[]; sz=zipfile.ZipFile(f'{R}/sigma/sigma-master.zip')
    for n in sz.namelist():
        if not (n.endswith('.yml') and '/rules' in n) or '/regression_data/' in n: continue   # regression_data/*/info.yml 은 테스트 메타(룰 아님)
        y=sz.read(n).decode('utf-8','ignore').splitlines(); d={'tags':[],'falsepositives':[],'logsource':{}}; cur=None; block=None
        for line in y:
            if block and (line.startswith('    ') or line.strip()==''): d[block]=(d.get(block,'')+line.strip()+' ').strip(); continue
            block=None
            m=re.match(r'^([a-z_]+):\s*(.*)$',line)
            if m:
                k,v=m.group(1),m.group(2).strip(); cur=k
                if v in ('|','>','|-','>-'): block=k; d[k]=''
                elif k in ('title','id','status','description','level','date','author'): d[k]=v.strip('\'"')
                continue
            m2=re.match(r'^    ([a-z_]+):\s*(.*)$',line)
            if m2 and cur=='logsource': d['logsource'][m2.group(1)]=m2.group(2).strip().strip('\'"'); continue
            m3=re.match(r'^    - (.*)$',line)
            if m3 and cur in ('tags','falsepositives'): d[cur].append(m3.group(1).strip().strip('\'"'))
        if d.get('title'): d['file']=n.split('/',1)[1]; d['parser']='minimal'; d['attack']=[t for t in d['tags'] if t.startswith('attack.')]; rows.append(d)
    wjsonl(f'{O}/knowledge/sigma_rules.jsonl',rows); kn['sigma_rules']=len(rows); kn['sigma_linux']=sum(1 for r in rows if r['logsource'].get('product')=='linux')
    # Atomic (minimal: 기법·display_name·테스트명·설명·플랫폼·executor·command)
    rows=[]
    for f in sorted(glob.glob(f'{R}/atomic-red-team/atomics/T*/T*.yaml')):
        y=open(f,encoding='utf-8',errors='ignore').read().splitlines(); tech=next((l.split(':',1)[1].strip() for l in y if l.startswith('attack_technique:')),None); disp=next((l.split(':',1)[1].strip().strip('\'"') for l in y if l.startswith('display_name:')),None)
        tests=[]; t=None; mode=None; indent=None
        for line in y:
            s=line.strip()
            if re.match(r'^- name:',line) and line.startswith('- name:'):
                t={'name':s.split(':',1)[1].strip().strip('\'"'),'description':'','platforms':[],'executor':None,'command':''}; tests.append(t); mode=None; continue
            if t is None: continue
            if re.match(r'^  description:\s*[|>]',line): mode='description'; continue
            if re.match(r'^  supported_platforms:',line): mode='platforms'; continue
            if re.match(r'^  executor:',line): mode='executor'; continue
            if mode=='platforms' and re.match(r'^  - ',line): t['platforms'].append(s[2:].strip()); continue
            if mode=='executor':
                if re.match(r'^    name:',line): t['executor']=s.split(':',1)[1].strip()
                if re.match(r'^    command:\s*[|>]',line): mode='command'; continue
            if mode=='command':
                if line.startswith('      '): t['command']+=line[6:]+'\n'; continue
                mode='executor' if line.startswith('    ') else None
            if mode=='description':
                if line.startswith('    '): t['description']+=s+' '; continue
                mode=None
            if re.match(r'^  [a-z_]+:',line) and mode in ('platforms',): mode=None
        rows.append({'technique':tech,'display_name':disp,'tests':tests,'n_tests':len(tests),'linux_tests':sum(1 for x in tests if 'linux' in x['platforms']),'file':os.path.relpath(f,R),'parser':'minimal'})
    wjsonl(f'{O}/knowledge/atomic_tests.jsonl',rows); kn['atomic_techniques']=len(rows); kn['atomic_tests']=sum(r['n_tests'] for r in rows); kn['atomic_linux_tests']=sum(r['linux_tests'] for r in rows)
    # ATT&CK STIX
    st=json.load(open(f'{R}/attack-stix/enterprise-attack.json')); objs=st['objects']; rows=[]
    for o in objs:
        if o.get('type')!='attack-pattern' or o.get('revoked') or o.get('x_mitre_deprecated'): continue
        ext=next((e for e in o.get('external_references',[]) if e.get('source_name')=='mitre-attack'),{})
        rows.append({'technique_id':ext.get('external_id'),'name':o.get('name'),'description':o.get('description',''),'tactics':[k.get('phase_name') for k in o.get('kill_chain_phases',[])],'platforms':o.get('x_mitre_platforms',[]),'detection':o.get('x_mitre_detection',''),'data_sources':o.get('x_mitre_data_sources',[]),'is_subtechnique':bool(o.get('x_mitre_is_subtechnique')),'url':ext.get('url')})
    wjsonl(f'{O}/knowledge/attack_techniques.jsonl',rows); kn['attack_techniques']=len(rows)
    # KEV
    kev=json.load(open(f'{R}/cisa-kev/known_exploited_vulnerabilities.json')); rows=kev.get('vulnerabilities',[])
    wjsonl(f'{O}/knowledge/cisa_kev.jsonl',rows); kn['cisa_kev']=len(rows)
    stats['knowledge']=kn; print(f"[knowledge] {kn}")

json.dump({'args':vars(A),'stats':stats},open(f'{O}/STATS.json','w'),ensure_ascii=False,indent=1)
print("STATS →", f'{O}/STATS.json')
