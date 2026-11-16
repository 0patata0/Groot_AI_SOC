"""Original forty recovery cases plus FIFO database/backup refusal."""
import importlib.util
import os
from pathlib import Path
import unittest

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('release_cache_tested','release_cache.py')
fixture=load('release_cache_fixture','test_cache_transaction.py')
# The unchanged forty-case suite now instantiates the adapter. The imported
# fixture's exception alias must reference the adapter's original module.
fixture.mod.Cache=m.Cache
fixture.mod.Refused=m.Refused


class CoordinatedCache(fixture.CacheTest):
    def test_fifo_database_is_refused_before_blocking_read(self):
        self.path.unlink();os.mkfifo(self.path)
        with self.assertRaisesRegex(m.Refused,'unsafe_cache_file'):self.cache.prepare()

    def test_fifo_backup_is_refused_before_blocking_read(self):
        self.cache.prepare();path=self.storage/'before.sqlite3';path.unlink();os.mkfifo(path)
        with self.assertRaisesRegex(m.Refused,'unsafe_cache_file'):self.cache.saved('before')


if __name__=='__main__':unittest.main()
