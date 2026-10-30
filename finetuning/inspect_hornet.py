"""Inspect selected Hornet Zeek JSON logs without inventing attack labels.

Requires complete acquisition manifests with pinned gzip/raw hashes. Keeps
missing fields distinct from zero/false and reports capture notices separately.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def decode(line):
    def invalid(value): raise ValueError('Non-finite JSON constant')
    value = json.loads(line, parse_float=Decimal, parse_constant=invalid,
                       object_pairs_hook=unique_object)
    if not isinstance(value, dict): raise ValueError('Expected JSON event object')
    return value


def epoch_seconds(value):
    if type(value) not in (Decimal, int): raise ValueError('Expected exact numeric timestamp')
    number = Decimal(value)
    if not number.is_finite() or not 0 <= number <= Decimal('100000000000'):
        raise ValueError('Timestamp outside supported range')
    if number.as_tuple().exponent < -18: raise ValueError('Unsupported timestamp precision')
    return number


def display_time(value):
    value = epoch_seconds(value)
    date = (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=int(value))).astimezone(timezone(timedelta(hours=9)))
    fraction = format(value, 'f').partition('.')[2]
    return date.strftime('%Y-%m-%dT%H:%M:%S') + ('.'+fraction if fraction else '') + '+09:00'


def endpoints(row):
    result = []
    for side in ('orig', 'resp'):
        address = ipaddress.ip_address(row['id.'+side+'_h'])
        port = row['id.'+side+'_p']
        if type(port) is not int or not 0 <= port <= 65535: raise ValueError('Invalid port')
        result.extend((str(address), port))
    return tuple(result)


def direction(row, own_addresses):
    source, _, target, _ = endpoints(row)
    a, b = source in own_addresses, target in own_addresses
    return 'self_to_self' if a and b else 'outbound' if a else 'inbound' if b else 'neither_endpoint_is_observer'


def auth_state(row):
    if 'auth_success' not in row: return 'missing'
    if type(row['auth_success']) is not bool: raise ValueError('Invalid auth_success type')
    return 'true' if row['auth_success'] else 'false'


def inspect(manifest, directory, own_addresses):
    if manifest.get('status') != 'complete': raise ValueError('Incomplete acquisition')
    own_addresses = {str(ipaddress.ip_address(x)) for x in own_addresses}
    if not own_addresses: raise ValueError('Observed host addresses are required')
    kinds=Counter(); states=Counter(); protocols=Counter(); directions=Counter(); missing=Counter()
    auth=Counter(); notices=Counter(); capture=Counter(); conns=defaultdict(list); ssh=[]; files=[]
    stats_drops=Counter(); maximum_drops=None; missing_stats=Counter(); missed=Counter()
    seen=set(); start=end=None; highest_loss=None; total_gaps=total_acks=0
    for member in manifest['members']:
        name=member['local_name']
        if Path(name).name != name or name in seen: raise ValueError('Unsafe or repeated local member')
        seen.add(name);path=directory/name
        if path.is_symlink(): raise ValueError('Source symlink rejected')
        data=path.read_bytes()
        if len(data)!=member['gzip_bytes'] or hashlib.sha256(data).hexdigest()!=member['gzip_sha256']:
            raise ValueError('Compressed member mismatch')
        raw=gzip.decompress(data)
        if len(raw)!=member['raw_bytes'] or hashlib.sha256(raw).hexdigest()!=member['raw_sha256']:
            raise ValueError('Raw member mismatch')
        kind=Path(member['member']).name.split('.')[0]
        if kind not in ('conn','ssh','notice','capture_loss','stats'): raise ValueError('Unexpected log kind')
        rows=0;offset=0
        for number,line in enumerate(raw.splitlines(keepends=True),1):
            row=decode(line);ts=epoch_seconds(row['ts']);rows+=1;kinds[kind]+=1
            start=ts if start is None else min(start,ts);end=ts if end is None else max(end,ts)
            ref={'member':member['member'],'line':number,'byte_offset':offset,'raw_line_sha256':hashlib.sha256(line).hexdigest()}
            if kind=='conn':
                directions[direction(row,own_addresses)]+=1;protocols[row['proto']]+=1;states[row['conn_state']]+=1
                for field in ('duration','orig_bytes','resp_bytes','service','missed_bytes'):
                    if field not in row: missing[field]+=1
                if 'missed_bytes' not in row: missed['missing']+=1
                else:
                    if type(row['missed_bytes']) is not int or row['missed_bytes']<0: raise ValueError('Invalid missed byte count')
                    missed['zero_reported' if row['missed_bytes']==0 else 'positive_reported']+=1
                conns[row['uid']].append((endpoints(row),row['proto'],ref))
            elif kind=='ssh':
                auth[auth_state(row)]+=1;ssh.append((row['uid'],endpoints(row),ref))
            elif kind=='notice': notices[row['note']]+=1
            elif kind=='capture_loss':
                loss=Decimal(row['percent_lost'])
                if not loss.is_finite() or loss<0: raise ValueError('Invalid observed capture loss')
                for field in ('gaps','acks'):
                    if type(row[field]) is not int or row[field]<0: raise ValueError('Invalid capture counter')
                capture['zero_reported' if loss==0 else 'positive_reported']+=1
                highest_loss=loss if highest_loss is None else max(highest_loss,loss)
                total_gaps+=row['gaps'];total_acks+=row['acks']
            elif kind=='stats':
                if 'pkts_dropped' not in row: missing_stats['pkts_dropped']+=1
                else:
                    count=row['pkts_dropped']
                    if type(count) is not int or count<0: raise ValueError('Invalid reported packet drops')
                    stats_drops['zero_reported' if count==0 else 'positive_reported']+=1
                    maximum_drops=count if maximum_drops is None else max(maximum_drops,count)
            offset+=len(line)
        if rows!=member['rows']: raise ValueError('Row count mismatch')
        files.append({'member':member['member'],'rows':rows,'raw_sha256':member['raw_sha256']})
    links=Counter();examples=[]
    for uid,peer,ref in ssh:
        candidates=conns.get(uid,[])
        matching=[r for r in candidates if r[0]==peer and r[1]=='tcp']
        state='unique_uid_tuple_match' if len(candidates)==len(matching)==1 else 'missing_uid' if not candidates else 'ambiguous_or_endpoint_mismatch'
        links[state]+=1
        if len(examples)<4:examples.append({'ssh':ref,'state':state,'conn':[c[2] for c in matching]})
    return {'geo':manifest['geo'],'date_selected':manifest['date_selected'],'files':files,
            'rows_by_kind':dict(kinds),'protocols':dict(protocols),'connection_states':dict(states),
            'observer_relative_directions':dict(directions),'missing_connection_fields':dict(missing),
            'ssh_auth_success_observations':dict(auth),'ssh_connection_links':dict(links),'link_examples':examples,
            'notice_types':dict(notices),'capture_loss_observations':dict(capture),
            'conn_missed_byte_observations':dict(missed),'stats_drop_observations':dict(stats_drops),
            'stats_max_reported_pkts_dropped':maximum_drops,'stats_missing_fields':dict(missing_stats),
            'capture_loss_max_reported_percent':str(highest_loss) if highest_loss is not None else None,
            'capture_reported_gaps_sum':total_gaps,'capture_reported_acks_sum':total_acks,
            'first_event_kst':display_time(start) if start is not None else None,
            'last_event_kst':display_time(end) if end is not None else None,
            'duplicate_connection_uid_records':sum(len(v)-1 for v in conns.values()),
            'attack_verdicts_generated':0,'missing_values_filled':False,
            'limitations':['No per-flow adjudicated attack/benign labels inferred.',
                           'Authentication observation is not business authorization or proof of compromise.',
                           'Zero loss estimates and no exact alerts do not establish complete capture or benign activity.',
                           'Source addresses are historical observations, not current blocklist entries.',
                           'The filename day is selection metadata, not proof of its timezone.']}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--directory',type=Path,required=True)
    p.add_argument('--own-ip',action='append',required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if args.output.exists():p.error('Output already exists')
    result=inspect(json.loads(args.manifest.read_text()),args.directory,args.own_ip)
    with args.output.open('x') as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('files','link_examples')}))


if __name__=='__main__':main()
