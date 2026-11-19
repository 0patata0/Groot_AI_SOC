"""Create a context-only alias of an already local DGX model, via administrator231."""
import json
import re
import subprocess
import urllib.request


def ensure_alias(base,source,expected,alias,context):
    try:
        from .kali_hermes import NoRedirect,need
    except ImportError:
        from kali_hermes import NoRedirect,need
    need(source and alias and source!=alias and re.fullmatch(r'[A-Za-z0-9_.:/+-]{1,256}',source)
         and re.fullmatch(r'[A-Za-z0-9_.:/+-]{1,256}',alias),'distinct_model_names_required')
    need(expected and re.fullmatch('[a-f0-9]{64}',expected),'source_digest_required')
    need(context==65536,'hermes_alias_context_must_be_65536')
    addresses=json.loads(subprocess.check_output(['/usr/sbin/ip','-j','address','show'],text=True,timeout=10))
    need(any(address.get('local')=='192.168.16.231'for interface in addresses
             for address in interface.get('addr_info',[])),'administrator231_required')
    client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    root=base.removesuffix('/v1')
    def request(path,body=None):
        data=json.dumps(body).encode()if body is not None else None
        call=urllib.request.Request(root+path,data=data,headers={'Content-Type':'application/json'})
        with client.open(call,timeout=60)as response:
            raw=response.read(4194305)
            need(response.status==200 and len(raw)<=4194304,'model_api_response_bound')
            return json.loads(raw)
    def inventory():
        rows=request('/api/tags')['models']
        need(len(rows)<=256,'model_inventory_bound')
        return {row['name']:row['digest']for row in rows}
    def parameters(row):
        result={}
        for line in row.get('parameters','').splitlines():
            key,value=line.split(None,1)
            result[key]=value
        return result
    def weights(row):
        matches=re.findall(r'(?m)^FROM\s+.*sha256-([a-f0-9]{64})\s*$',row.get('modelfile',''))
        need(len(matches)==1,'local_weight_identity_unavailable')
        return matches[0]
    before=inventory()
    need(before.get(source)==expected,'source_model_digest_mismatch')
    original=request('/api/show',{'model':source})
    source_parameters=parameters(original)
    source_weights=weights(original)
    created=alias not in before
    if created:
        reply=request('/api/create',{'model':alias,'from':source,'parameters':{'num_ctx':context},'stream':False})
        need(reply.get('status')=='success','model_alias_creation_failed')
    after=inventory()
    need(all(after.get(name)==sha for name,sha in before.items()),'existing_models_changed_during_alias_creation')
    configured=request('/api/show',{'model':alias})
    configured_parameters=parameters(configured)
    need(configured_parameters=={**source_parameters,'num_ctx':str(context)},'alias_parameters_mismatch')
    need(weights(configured)==source_weights,'alias_weights_mismatch')
    for key in ('template','system','model_info','capabilities'):
        need(configured.get(key)==original.get(key),'alias_model_metadata_mismatch:'+key)
    details=dict(configured.get('details',{}))
    need(details.pop('parent_model',None)==source,'alias_parent_model_mismatch')
    source_details=dict(original.get('details',{}))
    source_details.pop('parent_model',None)
    need(details==source_details,'alias_model_metadata_mismatch:details')
    return {'source_model':source,'source_digest':expected,'alias':alias,'alias_digest':after[alias],
            'num_ctx':context,'same_weight_blob_sha256':source_weights,'created':created,
            'existing_model_digests_unchanged':True,'route':'administrator231 -> DGX model API',
            'weight_downloads':0,'service_restarts':0}
