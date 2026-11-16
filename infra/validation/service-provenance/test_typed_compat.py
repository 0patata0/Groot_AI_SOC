"""Run the exact parent36 assertions with a schema-aware mock response.

The pinned parent mock predates the typed partial lookup schema. Only its
model response factory is adapted; no assertion, dispatch or guard is changed.
"""
from pathlib import Path
import hashlib,os
source=Path(os.environ.get('SOC_TYPED_TEST',Path(__file__).parents[3]/'infra/validation/typed-service/test_typed_service.py'))
raw=source.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='092bdbfbc58bc43a6a7d21470c6c7cc40175795602768a38b427e69bc883038b'
text=raw.decode();needle="     return {'more_evidence':False,'report':{'assessment':'unresolved'"
assert text.count(needle)==1
insertion="     fields=schema.get('properties',{}).get('report',{}).get('properties',{})\n     if fields and all('const' in value for value in fields.values()):return {'more_evidence':False,'report':{key:value['const'] for key,value in fields.items()}}\n"
text=text.replace(needle,insertion+needle,1)
__file__=str(source)
exec(compile(text,str(source)+':schema_aware_mock','exec'),globals())
