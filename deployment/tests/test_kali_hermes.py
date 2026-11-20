"""Offline input admission must fail before writes or network acquisition."""
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from deployment import kali_hermes as installer


class OfflineAdmission(unittest.TestCase):
    def archive(self,path,rows):
        with tarfile.open(path,'w')as archive:
            for name,link in rows:
                row=tarfile.TarInfo(name)
                if link is not None:
                    row.type=tarfile.SYMTYPE
                    row.linkname=link
                    archive.addfile(row)
                else:
                    row.size=1
                    archive.addfile(row,io.BytesIO(b'x'))

    def test_bad_digest_leaves_install_destination_absent(self):
        with tempfile.TemporaryDirectory()as task:
            task=Path(task)
            bundle=task/'bundle.tar'
            bundle.write_bytes(b'not an admitted archive')
            with self.assertRaisesRegex(ValueError,'digest_mismatch'):
                installer.install_offline(bundle,'0'*64,task/'home')
            self.assertFalse((task/'home').exists())

    def test_no_online_install_fallback(self):
        with patch.object(installer.subprocess,'run')as run:
            with self.assertRaisesRegex(ValueError,'offline_bundle_and_sha256_required'):
                installer.install_offline(None,None,Path('/unused'))
            run.assert_not_called()

    def test_traversal_rejected_before_earlier_member_is_written(self):
        with tempfile.TemporaryDirectory()as task:
            task=Path(task)
            archive=task/'bad.tar'
            self.archive(archive,[('apparently-safe',None),('../outside',None)])
            with self.assertRaisesRegex(ValueError,'unsafe_archive_path'):
                installer.extract(archive,task/'out')
            self.assertFalse((task/'out').exists())
            self.assertFalse((task/'outside').exists())

    def test_duplicate_members_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory()as task:
            task=Path(task)
            archive=task/'bad.tar'
            self.archive(archive,[('same',None),('same',None)])
            with self.assertRaisesRegex(ValueError,'unsafe_archive_path'):
                installer.extract(archive,task/'out')
            self.assertFalse((task/'out').exists())

    def test_source_link_escape_and_outer_links_rejected(self):
        for link,regular_only,reason in [('../../outside',False,'escaping_archive_link'),
                                       ('inside',True,'unsafe_archive_type')]:
            with self.subTest(link=link),tempfile.TemporaryDirectory()as task:
                task=Path(task)
                archive=task/'bad.tar'
                self.archive(archive,[('link',link)])
                with self.assertRaisesRegex(ValueError,reason):
                    installer.extract(archive,task/'out',regular_only)
                self.assertFalse((task/'out').exists())

    def test_offline_children_do_not_inherit_proxy_or_index_settings(self):
        with patch.dict(os.environ,{'HTTPS_PROXY':'https://example.invalid',
                                   'PIP_INDEX_URL':'https://example.invalid',
                                   'UV_INDEX_URL':'https://example.invalid'},clear=True):
            environment=installer.offline_environment()
        self.assertNotIn('HTTPS_PROXY',environment)
        self.assertNotIn('PIP_INDEX_URL',environment)
        self.assertNotIn('UV_INDEX_URL',environment)
        self.assertEqual(environment['UV_OFFLINE'],'1')
        self.assertEqual(environment['PIP_NO_INDEX'],'1')

    def test_unsupported_small_context_rejected_before_live_configuration(self):
        with patch('sys.argv',['kali_hermes.py','--configure','--model','model:tag',
                               '--api-base-url','http://example.invalid:11434/v1',
                               '--context-length','32768','--plan']):
            with self.assertRaisesRegex(ValueError,'at_least_64000'):
                installer.main()

    def test_symlinked_user_data_rejected_before_config_or_endpoint_access(self):
        with tempfile.TemporaryDirectory()as task:
            task=Path(task)
            home=task/'home';home.mkdir()
            outside=task/'outside';outside.mkdir()
            marker=outside/'config.yaml';marker.write_text('preserve this configuration')
            (home/'.hermes').symlink_to(outside,target_is_directory=True)
            with patch.object(installer,'local_user',return_value=(None,home)),\
                 patch.object(installer,'models')as models,\
                 patch('sys.argv',['kali_hermes.py','--configure','--model','model:tag',
                                   '--api-base-url','http://example.invalid:11434/v1']):
                with self.assertRaisesRegex(ValueError,'owned_hermes_data_required'):
                    installer.main()
                models.assert_not_called()
            self.assertEqual(marker.read_text(),'preserve this configuration')


class CliRegistration(unittest.TestCase):
    def test_zsh_preserves_existing_bytes_and_is_idempotent(self):
        with tempfile.TemporaryDirectory()as task:
            home=Path(task).resolve()
            original=b'# user configuration\nsetopt autocd'
            rc=home/'.zshrc';rc.write_bytes(original);rc.chmod(0o640)
            profile=home/'.profile';profile.write_bytes(b'# bash login: preserve\n')
            result=installer.register_cli_path(home,'/usr/bin/zsh')
            self.assertEqual({row['file']for row in result['changed']},{'.zprofile','.zshrc'})
            self.assertEqual(rc.read_bytes(),original+b'\n'+installer.CLI_PATH_BLOCK.encode())
            self.assertEqual(rc.stat().st_mode&0o777,0o640)
            self.assertEqual((Path(result['backup'])/'.zshrc').read_bytes(),original)
            self.assertEqual(profile.read_bytes(),b'# bash login: preserve\n')
            hashes={name:installer.digest(home/name)for name in ('.zprofile','.zshrc')}
            self.assertEqual(installer.register_cli_path(home,'/bin/zsh'),{'changed':[],'backup':None})
            self.assertEqual(hashes,{name:installer.digest(home/name)for name in hashes})

    def test_symlinked_second_profile_rejected_before_first_profile_write(self):
        with tempfile.TemporaryDirectory()as task:
            root=Path(task).resolve();home=root/'home';home.mkdir()
            outside=root/'outside';outside.write_text('preserve')
            (home/'.zshrc').symlink_to(outside)
            with self.assertRaisesRegex(ValueError,'symlinked_shell_startup'):
                installer.register_cli_path(home,'/usr/bin/zsh')
            self.assertFalse((home/'.zprofile').exists())
            self.assertFalse((home/'.local').exists())
            self.assertEqual(outside.read_text(),'preserve')

    def test_modified_managed_block_is_not_silently_replaced(self):
        with tempfile.TemporaryDirectory()as task:
            home=Path(task).resolve()
            rc=home/'.zshrc';rc.write_text('# >>> capstone-hermes user CLI >>>\ncustom\n')
            with self.assertRaisesRegex(ValueError,'modified_managed_shell_block'):
                installer.register_cli_path(home,'/bin/zsh')
            self.assertFalse((home/'.zprofile').exists())
            self.assertEqual(rc.read_text(),'# >>> capstone-hermes user CLI >>>\ncustom\n')

    def test_bash_uses_existing_login_profile_without_shadowing_it(self):
        with tempfile.TemporaryDirectory()as task:
            home=Path(task).resolve()
            (home/'.bash_login').write_text('# existing bash login\n')
            (home/'.profile').write_text('# preserve unused profile\n')
            result=installer.register_cli_path(home,'/usr/bin/bash')
            self.assertEqual({row['file']for row in result['changed']},{'.bash_login','.bashrc'})
            self.assertFalse((home/'.bash_profile').exists())
            self.assertEqual((home/'.profile').read_text(),'# preserve unused profile\n')

    def test_unsupported_shell_fails_without_writes(self):
        with tempfile.TemporaryDirectory()as task:
            home=Path(task).resolve()
            with self.assertRaisesRegex(ValueError,'unsupported_login_shell'):
                installer.register_cli_path(home,'/usr/bin/fish')
            self.assertEqual(list(home.iterdir()),[])

    def test_path_block_in_real_shells_preserves_order_and_avoids_duplicates(self):
        local=str(Path.home()/'.local/bin')
        for shell in ('zsh','bash'):
            executable=shutil.which(shell)
            if not executable:
                self.fail(shell+' required for PATH block verification')
            flags=['-f','-c']if shell=='zsh'else['--noprofile','--norc','-c']
            for before,expected in [('/usr/bin:/bin',local+':/usr/bin:/bin'),
                                    ('/usr/bin:'+local+':/bin','/usr/bin:'+local+':/bin')]:
                with self.subTest(shell=shell,before=before):
                    command=installer.CLI_PATH_BLOCK*2+'printf "%s\\n" "$PATH"'
                    result=subprocess.run([executable,*flags,command],capture_output=True,text=True,
                                          timeout=10,env=dict(os.environ,PATH=before))
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertEqual(result.stdout.strip(),expected)


if __name__=='__main__':
    unittest.main()
