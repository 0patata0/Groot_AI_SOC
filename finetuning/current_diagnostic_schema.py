"""Audit the registered diagnostic history guards without installing a validator.

Only this exact guard structure is supported. Unknown schema constructs remain
rejected by the existing corpus auditor; no runtime schema or permission changes.
"""
import copy
from prepare_data import Reject

NAME='mcp__system_diagnostics__get_system_diagnostics'


def project_for_call(name, schema, arguments):
    if name!=NAME or 'dependentRequired' not in schema:return schema
    expected={'since_kst':['until_kst'],'until_kst':['since_kst']}
    guards=schema.get('allOf')
    if schema['dependentRequired']!=expected or not isinstance(guards,list) or len(guards)!=3:
        raise Reject('unrecognized_diagnostic_guard')
    if guards[:2]!=[{'not':{'required':['lookback_minutes','since_kst']}},
                    {'not':{'required':['lookback_minutes','until_kst']}}]:
        raise Reject('unrecognized_diagnostic_guard')
    condition=guards[2]
    if set(condition)!={'if','then'} or condition['if']!={'required':['since_kst']}:
        raise Reject('unrecognized_diagnostic_guard')
    then=condition['then']
    if set(then)!={'properties','type','required'} or then['type']!='object' or then['required']!=[]:
        raise Reject('unrecognized_diagnostic_guard')
    if set(then['properties'])!={'target'} or set(then['properties']['target'])!={'enum'}:
        raise Reject('unrecognized_diagnostic_guard')
    targets=then['properties']['target']['enum']
    if not isinstance(targets,list) or not targets or not all(isinstance(x,str) for x in targets):
        raise Reject('invalid_diagnostic_history_targets')
    if not isinstance(arguments,dict):raise Reject('arguments_schema_mismatch')
    has_since='since_kst' in arguments;has_until='until_kst' in arguments
    if has_since!=has_until or ((has_since or has_until) and 'lookback_minutes' in arguments):
        raise Reject('arguments_schema_mismatch')
    if has_since and arguments.get('target') not in targets:raise Reject('arguments_schema_mismatch')
    projected=copy.deepcopy(schema);projected.pop('allOf');projected.pop('dependentRequired')
    annotation=projected['properties']['target'].pop('x-capstone-current-companions',None)
    if annotation is not None and (not isinstance(annotation,dict) or
       any(not isinstance(k,str) or not isinstance(v,list) or not all(isinstance(x,str) for x in v)
           for k,v in annotation.items())):raise Reject('invalid_diagnostic_annotation')
    return projected
