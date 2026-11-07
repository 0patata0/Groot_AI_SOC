"""Native chat must retain exact inventory arguments and honest failures."""
import copy,importlib.util,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
from test_soc_management_selection import w,agent,request
try:
    from jsonschema import Draft202012Validator as V
except ImportError:
    V=None
sys.path.insert(0,str(Path(__file__).parents[1]/'ollama-trial'))
import harness as H
from test_security_inventory import fixture
import review_channel_worker as worker

NAME='mcp__rule_b__get_security_rules'
QUESTION='Wazuh 상관분석 룰 첫 5개만 표로'

class InventoryRead(unittest.TestCase):
    @unittest.skipUnless(V, "existing Linux jsonschema dependency required")
    def test_first_native_selection_rejects_fabricated_snapshot_and_scope(self):
        a=agent();a.valid_tool_names={NAME,'mcp__resp__get_firewall_rules'}
        r=request();r['tools']=[{'type':'function','function':{'name':n,'parameters':{'type':'object','properties':{},'additionalProperties':True}}} for n in sorted(a.valid_tool_names)]
        env={'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_CHAT_READ_JSON':json.dumps({'request':QUESTION,'background':'FW 이전 답변','tools':[NAME],'requested_at_kst':'2026-11-07T15:00:00+09:00'})}
        before=copy.deepcopy(r)
        with patch.dict(w.os.environ,env,clear=True),patch.object(w,'chat_lookup_harness',return_value=H):
            out=w.management_read_request(r,a,pending=True)
        schema=out['response_format']['json_schema']['schema'];V.check_schema(schema)
        nonce=a._capstone_management_selection['nonce']
        good={'target':'b:wazuh','origin':'all','view':'details','correlation_only':True,'offset':0,'limit':5}
        def valid(args,name=NAME):return V(schema).is_valid({'request_nonce':nonce,'calls':[{'tool':name,'arguments':args}]})
        self.assertTrue(valid(good))
        for change in ({'snapshot_id':'0'*64},{'target':'a:waf'},{'view':'summary'},{'limit':20},{'origin':'custom'},{'offset':5}):
            self.assertFalse(valid(dict(good,**change)),change)
        self.assertFalse(valid({},'mcp__resp__get_firewall_rules'));self.assertEqual(r,before)

    def test_wrong_or_failed_read_cannot_be_presented_as_requested_inventory(self):
        for calls in ([],[{'server':'rule-b','name':'get_security_rules','arguments':{'target':'b:wazuh'},'is_error':True,'result':'{}'}]):
            text=worker.incomplete_inventory_text(H,QUESTION,calls)
            self.assertIn('b:wazuh',text);self.assertIn('완료하지 못했습니다',text);self.assertNotIn('FW 전체',text)
        self.assertIsNone(worker.incomplete_inventory_text(H,QUESTION,[fixture(view='details',correlation=True,limit=5)]))
        self.assertIsNone(worker.incomplete_inventory_text(H,'왜 장애가 발생했는지 조사해줘',[]))

    def test_model_completed_without_inventory_is_still_partial(self):
        import io
        from contextlib import nullcontext
        from types import SimpleNamespace as NS
        class DB:
            def execute(self,sql,args=()):
                if 'tool_calls' in sql:return []
                return NS(fetchone=lambda:None if 'SELECT 1' in sql else {'id':'c'*32,'mode':'verify','run_count':0,'session_id':None})
            def commit(self):pass
        store=NS(db=DB(),locked=lambda:nullcontext(),reporting=lambda _:nullcontext(),new_case=lambda *a:'c'*32,context=lambda _:[],close=lambda:None)
        controller=NS(Store=lambda _:store,digest=lambda _:'b'*64,TOOLSETS=('all',),run_hermes=lambda *a:{'completed':True,'state':'completed','text':'FW 전체 정상','run_id':'d'*32},prompt_for=lambda *a:'prompt')
        req={'id':'a'*32,'phase':'lead','question':QUESTION};out=io.StringIO()
        with patch.dict(sys.modules,{'harness':H,'soc_management_controller':controller}),patch.object(sys,'argv',['worker','hermes']),patch.object(sys,'stdin',NS(buffer=io.BytesIO(json.dumps(req).encode()))),patch.object(sys,'stdout',out),patch.object(worker.os,'geteuid',return_value=0),patch.object(worker,'read_trace_calls',return_value=[]):
            worker.main()
        report=json.loads(out.getvalue());self.assertEqual(report['status'],'partial');self.assertFalse(report['structured_scope_complete']);self.assertIsNone(report['evidence']);self.assertNotIn('FW 전체 정상',report['final_response'])

if __name__=='__main__':unittest.main(verbosity=2)
