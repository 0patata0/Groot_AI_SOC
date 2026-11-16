"""Build a phase-gated temporary relay for a coordinator's exact release.

Reuse the frozen generic reader bridge; do not alter the canonical reader or
shell launcher. This builder has no CLI, deployment, service or cache writes.
"""
import ast
import hashlib
import importlib.util
from pathlib import Path

HERE=Path(__file__).parent
SPEC=importlib.util.spec_from_file_location('release_gated_bridge',HERE/'reader_bridge.py')
bridge=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(bridge)
BASE_SHA='062b675e3398eb75a323e2618a34c549396ffee7927c7ff04a2318702b9adede'

GATE='''
def _release_normal_gate():
    value=_client({'schema':1,'host':_BOUND_RELEASE['host'],'release_id':_BOUND_RELEASE['release_id']})
    _need(value['source_contract_sha256']==_BOUND_RELEASE['source_contract_sha256'],'release_source_contract')
    observed=(value['phase'],value['generation'],value['cache']['status'],value['cache']['source_filter_policy'])
    _need(observed in (('staged','baseline','observed',None),
                      ('rolled_back','baseline','observed',None),
                      ('confirmed','candidate','observed','application-severity-v1')),'normal_reads_quiesced')
'''


def build(original,expected_sha256,*,host,release_id,source_contract_sha256):
    if hashlib.sha256((HERE/'reader_bridge.py').read_bytes()).hexdigest()!=BASE_SHA:
        raise ValueError('bridge_source_changed')
    bridge.contract.request({'schema':1,'host':host,'release_id':release_id})
    if not isinstance(source_contract_sha256,str)or not bridge.contract.HEX.fullmatch(source_contract_sha256):
        raise ValueError('source_contract_digest')
    tree=ast.parse(bridge.build(original,expected_sha256))
    mains=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main']
    if len(mains)!=1:raise ValueError('bridge_main_shape')
    main=mains[0];last=main.body[-1]
    if not(isinstance(last,ast.Expr)and isinstance(last.value,ast.Call)
           and isinstance(last.value.func,ast.Attribute)and last.value.func.attr=='main'
           and isinstance(last.value.func.value,ast.Name)and last.value.func.value.id=='original'
           and not last.value.args and not last.value.keywords):raise ValueError('bridge_main_shape')
    main.body.insert(-1,ast.Expr(ast.Call(ast.Name('_release_normal_gate',ast.Load()),[],[])))
    index=next(i for i,n in enumerate(tree.body)if isinstance(n,ast.If)
               and isinstance(n.test,ast.Compare)and isinstance(n.test.left,ast.Name)and n.test.left.id=='__name__')
    bound={'host':host,'release_id':release_id,'source_contract_sha256':source_contract_sha256}
    additions=ast.parse('_BOUND_RELEASE='+repr(bound)+'\n'+GATE).body
    tree.body[index:index]=additions;ast.fix_missing_locations(tree)
    source=(ast.unparse(tree)+'\n').encode();ast.parse(source)
    return source
