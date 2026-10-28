import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from memory_telemetry import collect,record


class Uninitialized:
    def is_initialized(self):return False
    def __getattr__(self,key):raise AssertionError('Diagnostic initialized or modified CUDA: '+key)


class Initialized:
    def is_initialized(self):return True
    def get_allocator_backend(self):return 'native'
    def memory_stats(self):return {'num_alloc_retries':49,'num_ooms':0,'reserved_bytes.all.current':1024,'unrelated_secret':'must not appear'}
    def mem_get_info(self):return 2**30,4*2**30


class TelemetryTests(unittest.TestCase):
    def test_segment_snapshot_distinguishes_vmm_from_missing_or_failed_data(self):
        class Snapshot(Initialized):
            def memory_snapshot(self):return [{'is_expandable':True},{'is_expandable':False}]
        class MissingFlag(Snapshot):
            def memory_snapshot(self):return [{}]
        class Failed(Snapshot):
            def memory_snapshot(self):raise RuntimeError('private path')
        for cuda,expected in ((Snapshot(),1),(MissingFlag(),None)):
            value=collect(cuda,phase='fixture')
            self.assertEqual(value['cuda']['status'],'available')
            self.assertEqual(value['cuda']['segments']['expandable'],expected)
        value=collect(Failed(),phase='fixture')
        self.assertEqual(value['cuda']['status'],'available')
        self.assertEqual(value['cuda']['segments']['status'],'unavailable')
        self.assertNotIn('private path',json.dumps(value))

    def test_uninitialized_cuda_is_never_initialized_or_reported_as_zero_use(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'meminfo').write_text('MemAvailable: 100 kB\nCmaFree: 6 kB\n');(root/'vmstat').write_text('oom_kill 1\n')
            (root/'memory.max').write_text('max');(root/'memory.events').write_text('oom_kill 0\n')
            value=collect(Uninitialized(),phase='before',proc=root,cgroup=root)
            self.assertEqual(value['cuda']['status'],'not_initialized');self.assertNotIn('free_bytes',value['cuda'])
            self.assertEqual(value['host_bytes']['values']['MemAvailable'],102400)
            self.assertEqual(value['vm_cumulative_counters']['values']['oom_kill'],1)
            self.assertEqual(value['cgroup']['memory.events']['values']['oom_kill'],0)
            self.assertIsNone(value['cgroup']['memory.max'])

    def test_recovered_allocation_retries_are_distinct_from_thrown_ooms(self):
        with tempfile.TemporaryDirectory() as folder:
            value=collect(Initialized(),phase='step',step=1,proc=Path(folder),cgroup=Path(folder))
        self.assertEqual(value['cuda']['allocator_counters']['num_alloc_retries'],49)
        self.assertEqual(value['cuda']['allocator_counters']['num_ooms'],0)
        self.assertEqual(value['cuda']['free_bytes'],2**30)
        self.assertNotIn('must not appear',json.dumps(value))
        self.assertEqual(value['host_bytes']['status'],'unavailable')

    def test_unavailable_driver_read_is_not_success_or_zero(self):
        class Broken(Initialized):
            def mem_get_info(self):raise RuntimeError('private details')
        with tempfile.TemporaryDirectory() as folder:
            value=collect(Broken(),phase='failure',proc=Path(folder),cgroup=Path(folder))
        self.assertEqual(value['cuda']['status'],'unavailable')
        self.assertEqual(value['cuda']['error_type'],'RuntimeError')
        self.assertNotIn('private details',json.dumps(value))
        self.assertNotIn('free_bytes',value['cuda'])

    def test_malformed_host_measurement_is_not_normalized_to_zero(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'meminfo').write_text('MemAvailable: invalid kB\n')
            value=collect(phase='failure',proc=root,cgroup=root)
        self.assertEqual(value['host_bytes']['status'],'unavailable')
        self.assertNotIn('values',value['host_bytes'])

    def test_failure_phase_appends_without_overwriting_prior_samples(self):
        with tempfile.TemporaryDirectory() as folder:
            record(folder,phase='model_loaded');record(folder,phase='training_failed',step=2,error_type='OutOfMemoryError')
            rows=[json.loads(line) for line in (Path(folder)/'memory_telemetry.jsonl').read_text().splitlines()]
        self.assertEqual([r['phase'] for r in rows],['model_loaded','training_failed'])
        self.assertEqual(rows[1]['error_type'],'OutOfMemoryError');self.assertEqual(rows[1]['step'],2)
        self.assertTrue(all(r['at_kst'].endswith('+09:00') for r in rows))

    def test_diagnostic_output_failure_is_visible_without_hiding_training_error(self):
        with patch.object(Path,'open',side_effect=PermissionError):value=record('/unused',phase='training_failed',error_type='OutOfMemoryError')
        self.assertEqual(value['recording_error'],'PermissionError')
        self.assertEqual(value['error_type'],'OutOfMemoryError')


if __name__=='__main__':unittest.main()
