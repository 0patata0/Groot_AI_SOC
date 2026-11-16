"""Actual local kernel no-replace behavior; no system service or live path."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location('release_atomic_tested',HERE/'release_atomic.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class AtomicCreate(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='release-atomic-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);self.addCleanup(os.close,self.fd)
        (self.root/'temporary').write_bytes(b'candidate bytes')

    def test_create_is_single_link_and_moves_the_temporary_name(self):
        m.create(self.fd,'temporary','published');self.assertEqual((self.root/'published').read_bytes(),b'candidate bytes')
        self.assertFalse((self.root/'temporary').exists());self.assertEqual((self.root/'published').stat().st_nlink,1)

    def test_collision_does_not_overwrite_existing_file(self):
        (self.root/'published').write_bytes(b'original bytes')
        with self.assertRaises(FileExistsError):m.create(self.fd,'temporary','published')
        self.assertEqual((self.root/'published').read_bytes(),b'original bytes');self.assertTrue((self.root/'temporary').exists())

    def test_destination_symlink_is_not_followed(self):
        (self.root/'published').symlink_to('victim')
        with self.assertRaises(FileExistsError):m.create(self.fd,'temporary','published')
        self.assertTrue((self.root/'published').is_symlink());self.assertFalse((self.root/'victim').exists())

    def test_source_link_fifo_and_path_expansion_are_rejected(self):
        (self.root/'alias').symlink_to('temporary')
        with self.assertRaisesRegex(ValueError,'atomic_create_source'):m.create(self.fd,'alias','published')
        os.mkfifo(self.root/'fifo')
        with self.assertRaisesRegex(ValueError,'atomic_create_source'):m.create(self.fd,'fifo','published')
        for value in ('../escape','/absolute','.','..','x/y','x\0y'):
            with self.assertRaisesRegex(ValueError,'atomic_create_scope'):m.create(self.fd,'temporary',value)

    def test_process_exit_immediately_after_publish_leaves_no_second_link(self):
        code="""import importlib.util,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('atomic_child',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
fd=os.open(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);m.create(fd,'temporary','published');os.fsync(fd);os._exit(23)
"""
        result=subprocess.run([sys.executable,'-I','-B','-c',code,str(HERE/'release_atomic.py'),str(self.root)],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,23);self.assertEqual((self.root/'published').stat().st_nlink,1)
        self.assertFalse((self.root/'temporary').exists())


if __name__=='__main__':unittest.main()
