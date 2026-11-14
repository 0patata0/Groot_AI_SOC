"""Audit the registered diagnostic history guards without installing a validator.

The registered legacy and current guard structures are supported. Unknown
constructs remain rejected; no runtime schema or permission changes occur.
"""
import copy
from prepare_data import Reject

NAME='mcp__system_diagnostics__get_system_diagnostics'
EVENT_NAMES={'mcp__security_events__search_suricata_alerts',
             'mcp__security_events__search_modsecurity_alerts',
             'mcp__security_events__search_wazuh_alerts',
             'mcp__security_events__search_web_access'}


def project_for_call(name, schema, arguments):
    if name in EVENT_NAMES and 'dependentRequired' in schema:
        if (schema['dependentRequired']!={'since_kst':['until_kst']} or
                schema.get('allOf')!=[{'not':{'required':['since_kst','lookback_minutes']}}]):
            raise Reject('unrecognized_event_time_guard')
        if not isinstance(arguments,dict):raise Reject('arguments_schema_mismatch')
        if 'since_kst'in arguments and ('until_kst'not in arguments or 'lookback_minutes'in arguments):
            raise Reject('arguments_schema_mismatch')
        projected=copy.deepcopy(schema);projected.pop('allOf');projected.pop('dependentRequired')
        return projected
    if name!=NAME or 'dependentRequired' not in schema:return schema
    expected={'since_kst':['until_kst'],'until_kst':['since_kst']}
    guards=schema.get('allOf')
    if schema['dependentRequired']!=expected or not isinstance(guards,list) or len(guards) not in (3,5):
        raise Reject('unrecognized_diagnostic_guard')
    if guards[:2]!=[{'not':{'required':['lookback_minutes','since_kst']}},
                    {'not':{'required':['lookback_minutes','until_kst']}}]:
        raise Reject('unrecognized_diagnostic_guard')
    if not isinstance(arguments,dict):raise Reject('arguments_schema_mismatch')
    if len(guards)==5:
        if guards[2:4]!=[
            {'if':{'required':['view']},'then':{'required':['since_kst','until_kst']}},
            {'if':{'required':['journal_scope']},'then':{'required':['view']}}]:
            raise Reject('unrecognized_diagnostic_guard')
        if (('view' in arguments and not {'since_kst','until_kst'}<=set(arguments))
                or ('journal_scope' in arguments and 'view' not in arguments)):
            raise Reject('arguments_schema_mismatch')
    condition=guards[-1]
    if set(condition)!={'if','then'} or condition['if']!={'required':['since_kst']}:
        raise Reject('unrecognized_diagnostic_guard')
    then=condition['then']
    if not (set(then)=={'properties'} or
            (set(then)=={'properties','type','required'} and then['type']=='object' and then['required']==[])):
        raise Reject('unrecognized_diagnostic_guard')
    if set(then['properties'])!={'target'} or set(then['properties']['target'])!={'enum'}:
        raise Reject('unrecognized_diagnostic_guard')
    targets=then['properties']['target']['enum']
    if not isinstance(targets,list) or not targets or not all(isinstance(x,str) for x in targets):
        raise Reject('invalid_diagnostic_history_targets')
    has_since='since_kst' in arguments;has_until='until_kst' in arguments
    if has_since!=has_until or ((has_since or has_until) and 'lookback_minutes' in arguments):
        raise Reject('arguments_schema_mismatch')
    if has_since and arguments.get('target') not in targets:raise Reject('arguments_schema_mismatch')
    projected=copy.deepcopy(schema);projected.pop('allOf');projected.pop('dependentRequired')
    for key in ('x-capstone-current-companions','x-capstone-service-labels'):
        annotation=projected['properties']['target'].pop(key,None)
        if annotation is not None and (not isinstance(annotation,dict) or
           any(not isinstance(k,str) or not isinstance(v,list) or not all(isinstance(x,str) for x in v)
               for k,v in annotation.items())):raise Reject('invalid_diagnostic_annotation')
    return projected
