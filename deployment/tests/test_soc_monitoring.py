import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

DEP=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(DEP))
import soc_monitoring as m


class MonitoringInstallerTests(unittest.TestCase):
    def test_no_added_packages_images_ports_or_model_privileges(self):
        for role in ('security','siem','service'):
            docs=m.units(role)
            for name,raw in docs.items():
                if not name.endswith('.service'):continue
                text=raw.decode()
                self.assertIn('User=root\n',text)
                self.assertIn('NoNewPrivileges=yes',text)
                self.assertIn('ProtectSystem=strict',text)
                self.assertIn('TimeoutStartSec=50',text)
                self.assertNotIn('sudo',text)
                self.assertNotIn('Listen',text)
                self.assertEqual('/var/log/capstone-vector/canary' in text,role=='security')
        self.assertEqual(m.units('service'),{})

    def test_model_and_ingestion_independent_units(self):
        docs=m.units('siem')
        self.assertEqual(set(docs),{'capstone-soc-model.service','capstone-soc-model.timer',
                                  'capstone-soc-ingestion.service','capstone-soc-ingestion.timer'})
        self.assertIn(b'OnUnitInactiveSec=300s',docs['capstone-soc-model.timer'])
        self.assertIn(b'OnUnitInactiveSec=60s',docs['capstone-soc-ingestion.timer'])

    def test_source_bundle_carries_every_probe_dependency(self):
        with patch.object(m.common,'read',side_effect=lambda path,*a,**k:Path(path).read_bytes()):
            files=m.files({'source':DEP.parent})
        self.assertEqual(len(files),8)
        self.assertIn(m.CODE/'canary/canary-validation.jq',files)
        self.assertIn(m.CODE/'pipeline_probe.py',files)

    def test_root_entry_transfers_webhook_directly_not_to_a_local_file(self):
        source=(DEP.parent/'deploy.sh').read_text()
        self.assertIn('siem monitor-export |\n  remote_role "$SECURITY_HOST" security monitor-activate',source)
        self.assertIn('security monitor-prepare |\n  remote_role "$SIEM_HOST" siem monitor-authorize',source)
        self.assertIn('security monitor-prepare |\n  remote_role "$SERVICE_HOST" service monitor-authorize',source)
        self.assertLess(source.index('siem diag-activate'),source.index('security monitor-configure'))

    def test_systemd_webhook_quotes_are_decoded_without_evaluation(self):
        value='http://10.0.0.10:8065/hooks/'+'x'*26
        for raw in (value,'"'+value+'"',"'"+value+"'"):
            def read(path,**kwargs):
                return b'{"layout":"groot"}' if str(path).endswith('runtime.json') else ('MM_WEBHOOK='+raw+'\nOTHER=ignored\n').encode()
            with patch.object(m.common,'read',side_effect=read),patch.object(m.common,'run',return_value=b'["MM_SERVICESETTINGS_SITEURL=https://chat.example.org"]'):
                self.assertEqual(m.export_webhook(),{'schema':1,'webhook':'https://chat.example.org/hooks/'+'x'*26})
        with patch.object(m.common,'read',return_value=b'MM_WEBHOOK=a\nMM_WEBHOOK=b\n'),self.assertRaises(ValueError):m.export_webhook()


if __name__=='__main__':unittest.main()
