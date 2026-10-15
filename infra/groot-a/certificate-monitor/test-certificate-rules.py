#!/usr/bin/env python3
"""Synthetic rules contract; --native uses existing B manager wazuh-logtest only.

No logger, monitored-file append, service restart, network request or rule install.
The caller must install the candidate in an authorized native sandbox/manager
before --native. Each fixture gets a fresh logtest session (ignore state resets).
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
RULES = HERE / 'capstone_certificate_rules.xml'
DECODERS = HERE / 'capstone_certificate_decoders.xml'
IDS = {str(n) for n in range(100300, 100306)}
LOCATION = '(groot-sec) any->journald'
EXPIRIES = ('ok', 'within_30_days', 'within_14_days', 'within_7_days', 'expired', 'unknown')
PROBES = ('verified', 'mismatch', 'unavailable')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def event(expiry='ok', probe='verified'):
    remaining = {'ok':2592001, 'within_30_days':2592000, 'within_14_days':1209600,
                 'within_7_days':604800, 'expired':0, 'unknown':None}[expiry]
    return {'schema_version':1, 'domain':'chat.grootlab.duckdns.org',
        'observed_at_utc':'2026-10-15T00:00:00Z', 'observed_at_kst':'2026-10-15T09:00:00+09:00',
        'expiry_status':expiry, 'probe_status':probe,
        'reason':{'verified':'verified','mismatch':'served_certificate_mismatch','unavailable':'tls_timeout'}[probe],
        'not_after_epoch':None if remaining is None else 1792022400 + remaining,
        'not_after_kst':None if remaining is None else '2026-11-14T09:00:00+09:00',
        'seconds_remaining':remaining, 'certificate_sha256':None if remaining is None else 'a'*64,
        'served_certificate_sha256':'a'*64 if probe=='verified' else ('b'*64 if probe=='mismatch' else None),
        'automatic_renewal':False}


def expected(expiry, probe):
    if expiry in ('within_14_days', 'within_7_days', 'expired'):
        return {'within_14_days':('100302',5),'within_7_days':('100303',7),'expired':('100304',10)}[expiry]
    if probe in ('mismatch','unavailable'):
        return '100305',5
    if expiry=='within_30_days':
        return '100301',3
    return '100300',0


def fixtures():
    rows=[]
    def add(name, payload, want, program='capstone-cert-monitor', location=LOCATION):
        rows.append({'name':name,'payload':payload,'expected':want,'program':program,'location':location})
    for expiry in EXPIRIES:
        for probe in PROBES:
            # unknown+verified is not emitted by the monitor. Keep it as a
            # base-only status-shape observation, not a healthy monitor claim.
            add(expiry+'_'+probe,canonical(event(expiry,probe)),expected(expiry,probe))
    for reason in ('certificate_unavailable','certificate_changed','certificate_invalid','hostname_invalid',
                   'not_yet_valid','checkend_failed','tls_verification_failed','served_certificate_invalid'):
        value=event('unknown','unavailable'); value['reason']=reason
        add('reason_'+reason,canonical(value),('100305',5))
    valid=canonical(event('expired','unavailable'))
    for name,program,location in (
        ('wrong_program','unrelated',LOCATION),('program_suffix','capstone-cert-monitor-extra',LOCATION),
        ('wrong_agent','capstone-cert-monitor','(groot-web) any->journald'),
        ('bare_location','capstone-cert-monitor','journald'),
        ('wrong_location','capstone-cert-monitor','(groot-sec) any->/var/log/unrelated.log')):
        add(name,valid,None,program,location)
    for key,value in (('domain','elsewhere.invalid'),('schema_version','1'),('schema_version',True),
                      ('automatic_renewal','false'),('automatic_renewal',True),('expiry_status','expired_extra'),
                      ('probe_status','unavailable_extra'),('reason','tls_timeout_extra'),
                      ('certificate_sha256',['a'*64]),('seconds_remaining','0')):
        data=event('expired','unavailable'); data[key]=value
        add('invalid_'+key+'_'+type(value).__name__,canonical(data),None)
    for key in ('domain','expiry_status','probe_status','reason','automatic_renewal'):
        data=event('expired','unavailable'); del data[key]
        add('missing_'+key,canonical(data),None)
    data=event('expired','unavailable'); data['extra_payload']='synthetic-only'
    add('extra_key',canonical(data),None)
    add('trailing_payload',valid+' trailing_payload',None)
    add('json_concatenation',valid+valid,None)
    add('duplicate_key',valid.replace('"schema_version":1','"schema_version":1,"schema_version":1'),None)
    add('noncanonical_spacing',json.dumps(event('expired','unavailable'),sort_keys=True),None)
    return rows


def static_contract(rows):
    decoder=ET.fromstring(DECODERS.read_bytes())
    assert decoder.tag=='decoder' and decoder.attrib=={'name':'capstone_certificate_json'}
    assert decoder.findtext('program_name')=='^capstone-cert-monitor$'
    assert decoder.findtext('prematch')==r'^\{'
    assert decoder.findtext('plugin_decoder')=='JSON_Decoder'
    # Wazuh OS_XML preserves element content bytes; ElementTree would silently
    # decode &gt; and conceal a native location mismatch. Pin the raw spelling.
    rule_bytes=RULES.read_bytes()
    assert br'<location type="pcre2">^\(groot-sec\) any->journald$</location>' in rule_bytes
    assert b'&gt;' not in rule_bytes
    root=ET.fromstring(rule_bytes)
    rules={r.attrib['id']:r for r in root.findall('rule')}
    assert set(rules)==IDS
    base=rules['100300']
    assert base.attrib['level']=='0' and base.findtext('decoded_as')=='capstone_certificate_json'
    assert base.findtext('program_name')=='^capstone-cert-monitor$'
    assert base.findtext('location')==r'^\(groot-sec\) any->journald$'
    assert [v.text for v in base.findall('options')]==['no_log']
    pattern=re.compile(base.findtext('match').replace(r'\z',r'\Z'))
    for row in rows:
        route = (row['program']=='capstone-cert-monitor' and row['location']==LOCATION)
        shape = pattern.fullmatch(row['payload']) is not None
        if row['expected'] is None:
            assert not route or not shape, row['name']
            continue
        assert route and shape, row['name']
        data=json.loads(row['payload']); matched=[]
        for sid,r in rules.items():
            if sid=='100300': continue
            assert r.findtext('if_sid')=='100300' and r.attrib['ignore']=='900'
            assert [v.text for v in r.findall('options')]==['no_email_alert','no_full_log']
            if all(re.fullmatch(f.text,str(data.get(f.attrib['name'],''))) for f in r.findall('field')):
                matched.append((sid,int(r.attrib['level'])))
        assert len(matched)<=1, (row['name'],'overlapping severity leaves')
        actual=matched[0] if matched else ('100300',0)
        assert actual==row['expected'],(row['name'],actual,row['expected'])
    return len(rows)


def native(rows, manager):
    assert re.fullmatch('[a-f0-9]{64}',manager), 'a fixed full manager CID is required'
    if sys.platform!='linux': raise RuntimeError('native mode requires the existing Linux host')
    passed=0
    for row in rows:
        line='Oct 15 09:00:00 groot-sec '+row['program']+'[12345]: '+row['payload']+'\n'
        command=['/usr/local/bin/docker','exec','-i',manager,'/var/ossec/bin/wazuh-logtest','-l',row['location']]
        try:
            completed=subprocess.run(command,input=line.encode(),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                                     timeout=20,check=False)
        except subprocess.TimeoutExpired:
            print(canonical({'status':'failed','case':row['name'],'reason':'native_timeout','new_operating_input':0}))
            return False,passed
        raw=completed.stdout
        if len(raw)>65536:
            print(canonical({'status':'failed','case':row['name'],'reason':'native_output_limit','new_operating_input':0}))
            return False,passed
        text=raw.decode('utf-8',errors='replace')
        ids=re.findall(r"^\s*id: '([0-9]+)'",text,re.M)
        levels=re.findall(r"^\s*level: '([0-9]+)'",text,re.M)
        clean=completed.returncode==0 and re.search(r'(?:ERROR|CRITICAL):',text) is None
        if row['expected'] is None:
            good=clean and not(set(ids)&IDS)
        else:
            sid,level=row['expected']
            good=clean and ids==[sid] and levels==[str(level)] and "name: 'capstone_certificate_json'" in text
        if not good:
            # Only the generated synthetic case is supplied to logtest. The
            # install controller stores this bounded diagnostic on B only.
            sys.stderr.buffer.write(raw)
            sys.stderr.buffer.flush()
            print(canonical({'status':'failed','case':row['name'],'expected':row['expected'],
                'actual_ids':ids,'actual_levels':levels,'exit_code':completed.returncode,
                'diagnostic_sha256':hashlib.sha256(raw).hexdigest(),'new_operating_input':0}))
            return False,passed
        passed+=1
        print(canonical({'status':'passed','case':row['name'],'expected':row['expected']}))
    return True,passed


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native',action='store_true')
    parser.add_argument('--manager',default='')
    args=parser.parse_args()
    rows=fixtures(); count=static_contract(rows)
    ok,passed=native(rows,args.manager) if args.native else (True,0)
    print(canonical({'schema_version':1,'status':'passed' if ok else 'failed','static_cases':count,
        'native_cases_passed':passed,'native_executed':args.native,
        'rules_sha256':hashlib.sha256(RULES.read_bytes()).hexdigest(),
        'decoders_sha256':hashlib.sha256(DECODERS.read_bytes()).hexdigest(),
        'new_operating_input':0,'rules_installed':False,'expired_live_e2e_tested':False,
        'expiry_seconds_recomputed_by_rules':False,'exactly_once_alert_delivery_claimed':False}))
    return 0 if ok else 1


if __name__=='__main__':
    raise SystemExit(main())
