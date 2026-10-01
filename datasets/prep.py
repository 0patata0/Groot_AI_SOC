#!/usr/bin/env python3
"""datasets/prep.py — 파인튜닝 전처리(재현 가능). 입력 datasets/raw/ → 출력 datasets/processed/ (gitignore).
 1) hermes-function-calling-v1: 5파일 conversations 해시 dedupe + 미정의 툴 호출 샘플 제거 → hermes_fc_v1.dedup.jsonl
 2) SALAD-SOC val: 악성 전부 + 양성 다운샘플(비율 --benign-ratio, source_dataset 층화) → salad_val.balanced.csv
 3) AIT-ADS: 환경별 Wazuh 경보에 labels.csv 시각 구간으로 phase_window 라벨, 환경 단위 split, normal 샘플 cap → ait/<env>.labeled.jsonl + split.json
사용: python3 datasets/prep.py [--seed 42] [--benign-ratio 1.0] [--ait-normal-cap 20000] [--ait-val wheeler] [--ait-holdout wilson]
"""
import argparse, csv, hashlib, io, json, os, random, re, zipfile, collections, datetime, sys
ap=argparse.ArgumentParser(); ap.add_argument('--seed',type=int,default=42); ap.add_argument('--benign-ratio',type=float,default=1.0)
ap.add_argument('--ait-normal-cap',type=int,default=20000); ap.add_argument('--ait-val',default='wheeler'); ap.add_argument('--ait-holdout',default='wilson')
ap.add_argument('--ait-phase-cap',type=int,default=5000, help='공격단계별 경보 상한(reservoir). dirb 홍수 억제')
ap.add_argument('--ait-window-pad',type=float,default=0.0, help='구간 앞뒤 여유(초). 탐지 지연 보정용, 기본 0')
ap.add_argument('--skip-ait',action='store_true'); A=ap.parse_args()
R='datasets/raw'; O='datasets/processed'; os.makedirs(O,exist_ok=True); os.makedirs(f'{O}/ait',exist_ok=True)
random.seed(A.seed); stats={}
TC=re.compile(r'<tool_call>\s*(\{.*?\})\s*</tool_call>', re.S)

# ---------- 1) hermes dedupe ----------
files=['func-calling-singleturn.json','func-calling.json','glaive-function-calling-5k.json','json-mode-agentic.json','json-mode-singleturn.json']
seen={}; out=[]; dup=0; unknown=0; total=0
for f in files:
    for s in json.load(open(f'{R}/hermes-function-calling-v1/{f}')):
        total+=1
        k=hashlib.sha1(json.dumps(s.get('conversations'),sort_keys=True,ensure_ascii=False).encode()).hexdigest()
        if k in seen: dup+=1; continue
        names=set()
        tools=s.get('tools')
        try:
            tl=json.loads(tools) if isinstance(tools,str) else tools
            for t in tl or []: names.add((t.get('function') or t).get('name'))
        except Exception: pass
        bad=False
        if names:
            for c in s.get('conversations',[]):
                if c.get('from')!='gpt': continue
                for m in TC.findall(c.get('value','')):
                    try: obj=json.loads(m)
                    except Exception: bad=True; break
                    if obj.get('name') not in names: bad=True; break
                if bad: break
        if bad: unknown+=1; continue
        seen[k]=f; s['_source_file']=f; out.append(s)
with open(f'{O}/hermes_fc_v1.dedup.jsonl','w',encoding='utf-8') as w:
    for s in out: w.write(json.dumps(s,ensure_ascii=False)+'\n')
stats['hermes']={'input':total,'duplicates_removed':dup,'unknown_tool_removed':unknown,'output':len(out),'by_file':dict(collections.Counter(s['_source_file'] for s in out))}
print(f"[hermes] {total} → dedupe -{dup}, 미정의툴 -{unknown} → {len(out)}")

# ---------- 2) SALAD balance ----------
rows=list(csv.DictReader(open(f'{R}/salad-soc/salad_val.csv',encoding='utf-8',errors='ignore')))
mal=[r for r in rows if r['is_malicious']=='True']; ben=[r for r in rows if r['is_malicious']!='True']
target=int(len(mal)*A.benign_ratio)
by_src=collections.defaultdict(list)
for r in ben: by_src[r['source_dataset']].append(r)
keep=[]
for src,lst in by_src.items():
    n=round(target*len(lst)/len(ben)); random.shuffle(lst); keep.extend(lst[:n])
bal=mal+keep; random.shuffle(bal)
with open(f'{O}/salad_val.balanced.csv','w',encoding='utf-8',newline='') as w:
    wr=csv.DictWriter(w,fieldnames=list(rows[0].keys())); wr.writeheader(); wr.writerows(bal)
tri=collections.Counter(r['triage_decision'] for r in bal)
stats['salad']={'input':len(rows),'malicious':len(mal),'benign_in':len(ben),'benign_kept':len(keep),'output':len(bal),'triage':dict(tri),'source':dict(collections.Counter(r['source_dataset'] for r in bal)),'note':'test 분할은 평가 전용(미다운로드). train 분할 받으면 동일 정책 적용'}
print(f"[salad] {len(rows)} → 악성 {len(mal)} + 양성 {len(keep)}(ratio {A.benign_ratio}) = {len(bal)} | triage {dict(tri)}")

# ---------- 3) AIT-ADS label + split ----------
if not A.skip_ait:
    zf=zipfile.ZipFile(f'{R}/ait-ads/ait_ads.zip')
    lab=collections.defaultdict(list)
    for r in csv.DictReader(open(f'{R}/ait-ads/labels.csv')): lab[r['scenario']].append((r['attack'],float(r['start']),float(r['end'])))
    envs=sorted(lab); split={'train':[e for e in envs if e not in (A.ait_val,A.ait_holdout)],'val':[A.ait_val],'holdout':[A.ait_holdout]}
    json.dump(split,open(f'{O}/ait/split.json','w'),indent=1)
    def ts(o):
        t=o.get('@timestamp') or ''
        try: return datetime.datetime.fromisoformat(t.replace('Z','+00:00')).timestamp()
        except Exception: return None
    aits={}
    for env in envs:
        wins=lab[env]; n=0; keep_attack=0; normal_seen=0; res=[]; phase_cnt=collections.Counter(); hi=0; bad_ts=0
        with zf.open(f'{env}_wazuh.json') as fh, open(f'{O}/ait/{env}.labeled.jsonl','w',encoding='utf-8') as w:
            pres=collections.defaultdict(list); pseen=collections.Counter()   # 단계별 reservoir
            for line in io.TextIOWrapper(fh,encoding='utf-8',errors='ignore'):
                line=line.strip()
                if not line: continue
                n+=1
                try: o=json.loads(line)
                except Exception: continue
                e=ts(o)
                if e is None: bad_ts+=1; continue
                pad=A.ait_window_pad
                phase=next((a for a,s,t in wins if s-pad<=e<=t+pad),None)
                o['ait_env']=env
                if phase:
                    o['phase_window']=phase; phase_cnt[phase]+=1; keep_attack+=1
                    if (o.get('rule') or {}).get('level',0)>=10: hi+=1
                    pseen[phase]+=1; lst=pres[phase]
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
            kept_phase={ph:len(l) for ph,l in pres.items()}
            for ph,l in pres.items():
                for o in l: w.write(json.dumps(o,ensure_ascii=False)+'\n')
            for o in res: w.write(json.dumps(o,ensure_ascii=False)+'\n')
        role='train' if env in split['train'] else ('val' if env in split['val'] else 'holdout')
        aits[env]={'split':role,'alerts':n,'bad_ts':bad_ts,'attack_window':keep_attack,'attack_level10plus':hi,'normal_seen':normal_seen,'normal_kept':len(res),'phases_in_window':dict(phase_cnt),'phases_kept':kept_phase,'file_MB':round(os.path.getsize(f'{O}/ait/{env}.labeled.jsonl')/1e6,1)}
        print(f"[ait] {env:16} {role:7} alerts={n:8} attack-window={keep_attack:7} → kept {sum(kept_phase.values()):6} (cap {A.ait_phase_cap}/phase) + normal {len(res):5}/{normal_seen:8} → {aits[env]['file_MB']}MB")
    stats['ait']={'split':split,'envs':aits,'note':'phase_window = labels.csv 시각 구간 기반(구간 내 노이즈 경보 포함 = 단계 컨텍스트 라벨, 경보 단위 악성 라벨 아님)'}

json.dump({'args':vars(A),'stats':stats},open(f'{O}/STATS.json','w'),ensure_ascii=False,indent=1)
print("STATS →", f'{O}/STATS.json')
