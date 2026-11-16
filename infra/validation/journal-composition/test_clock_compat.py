"""Run pinned clock assertions with only the intentional app-metadata description added.
Input schemas, other tool fields, clock and resource assertions remain exact.
"""
from pathlib import Path
import hashlib,os
source=Path(os.environ.get('SOC_FROZEN_CLOCK_TEST',Path(__file__).parents[3]/'infra/validation/diagnostic-read-boundaries/test_clock.py'))
raw=source.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='c0f23fd157daa28b2ec1c07a7e665422d26adf51601367cc898854213cc4db2a'
GUIDANCE='application_error records a parsed top-level application severity (logfmt/JSON), independent of journal priority. Declared severity is not proof of attack, data loss, root cause, current impact or recovery. History coverage is bound to source_filter_policy; legacy or different-policy windows are partial until rescanned. '
text=raw.decode()
needle='        self.assertEqual(m.tools(),old.tools())'
assert text.count(needle)==1
replacement="""        expected=old.tools()
        for tool in expected:
            if tool['name']=='get_system_diagnostics':
                marker='known_error_code controller_already_running'
                self.assertEqual(tool['description'].count(marker),1)
                tool['description']=tool['description'].replace(marker,GUIDANCE+marker,1)
        self.assertEqual(m.tools(),expected)"""
text=text.replace(needle,replacement,1)
__file__=str(source)
exec(compile(text,str(source)+':explicit_metadata_description','exec'),globals())
