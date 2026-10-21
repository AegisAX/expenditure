"""NAS 없이 전송 검증·재시도·보관 정책을 검증한다."""
import datetime
import importlib.util
from pathlib import Path
import shlex
import shutil
import tempfile
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfo

spec = importlib.util.spec_from_file_location('nas_upload', Path(__file__).resolve().parents[1] / 'tools/nas-upload.py')
nas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nas)


class FakeSFTP:
    def __init__(self):
        self.files = {'production': {}, 'development': {}}
        self.transfers = 0
        self.fail = False
        self.corrupt = False

    def directory(self, environment):
        return ['environment ' + environment]

    def listing(self, environment):
        return {name for name in self.files[environment] if nas.BACKUP_NAME.fullmatch(name)}

    def run(self, commands):
        environment = commands[0].split()[1]
        remote = self.files[environment]
        for cmd in commands[1:]:
            parts = shlex.split(cmd)
            if parts[0] == 'put':
                self.transfers += 1
                if self.fail:
                    raise RuntimeError('Simulated connection failure')
                remote[parts[2]] = Path(parts[1]).read_bytes()
            elif parts[0] == 'get':
                Path(parts[2]).write_bytes(b'corrupted' if self.corrupt else remote[parts[1]])
            elif parts[0] == 'rename':
                remote[parts[2]] = remote.pop(parts[1])
            elif parts[0] == 'rm':
                del remote[parts[1]]
        return ''


class UploadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.private = self.base / '.nas'
        self.private.mkdir()
        self.name = datetime.datetime.now(ZoneInfo('Asia/Seoul')).strftime('%Y%m%d-%H%M%S-%f') + '.tar.gz'
        for environment in ['production', 'development']:
            (self.base / environment).mkdir()
            (self.base / environment / self.name).write_bytes(b'backup-content')
        self.patch = patch.multiple(nas, PRIVATE=self.private)
        self.patch.start()
        self.sftp = FakeSFTP()
        self.config = {'host': 'nas', 'port': 54321, 'user': 'whitehat', 'remote_root': '/AegisAX_Backup', 'environment': 'production', 'local_dir': str(self.base / 'production'), 'remote_project': 'expenditure', 'remote_environment': 'production'}

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def test_upload_verify_skip_and_repair_missing_remote(self):
        self.assertEqual(nas.upload(self.config, self.sftp), 0)
        self.assertEqual(self.sftp.transfers, 1)
        self.assertEqual(nas.upload(self.config, self.sftp), 0)
        self.assertEqual(self.sftp.transfers, 1)
        del self.sftp.files['production'][self.name]
        self.assertEqual(nas.upload(self.config, self.sftp), 0)
        self.assertEqual(self.sftp.transfers, 2)

    def test_fail_and_retry_preserve_local_and_remote(self):
        old = '20000101-000000-000000.tar.gz'
        for remote in self.sftp.files.values():
            remote[old] = b'old'
        self.sftp.fail = True
        self.assertEqual(nas.upload(self.config, self.sftp), 1)
        self.assertTrue((self.base / 'production' / self.name).exists())
        self.assertIn(old, self.sftp.files['production'])
        self.sftp.fail = False
        self.assertEqual(nas.upload(self.config, self.sftp), 0)
        self.assertNotIn(old, self.sftp.files['production'])

    def test_hash_mismatch_is_not_committed(self):
        self.sftp.corrupt = True
        self.assertEqual(nas.upload(self.config, self.sftp), 1)
        self.assertNotIn(self.name, self.sftp.files['production'])
        self.assertFalse((self.private / 'uploaded.json').exists())

    def test_unrelated_remote_files_preserved(self):
        self.sftp.files['production']['unrelated.tar.gz'] = b'keep'
        self.assertEqual(nas.upload(self.config, self.sftp), 0)
        self.assertIn('unrelated.tar.gz', self.sftp.files['production'])

    def test_destination_change_reuploads(self):
        self.assertEqual(nas.upload(self.config, self.sftp), 0)
        self.config['remote_root'] = '/Different_Backup'
        self.assertEqual(nas.upload(self.config, self.sftp), 0)
        self.assertEqual(self.sftp.transfers, 2)

    def test_project_specific_nas_path(self):
        config = dict(self.config, remote_project='moiso', remote_environment='production')
        commands = nas.SFTP(config).directory('production')
        self.assertIn('cd moiso', commands)
        self.assertNotIn('cd expenditure', commands)
        self.assertIn('cd production', commands)

    def test_retention_keeps_29_days_and_removes_31_days(self):
        now = datetime.datetime.now(ZoneInfo('Asia/Seoul'))
        recent = (now - datetime.timedelta(days=29)).strftime('%Y%m%d-%H%M%S-%f') + '.tar.gz'
        expired = (now - datetime.timedelta(days=31)).strftime('%Y%m%d-%H%M%S-%f') + '.tar.gz'
        self.sftp.files['production'][recent] = b'keep'
        self.sftp.files['production'][expired] = b'expired'
        self.assertEqual(nas.upload(self.config, self.sftp), 0)
        self.assertIn(recent, self.sftp.files['production'])
        self.assertNotIn(expired, self.sftp.files['production'])

    def test_exact_30_days_and_path_validation(self):
        date = datetime.datetime(2026, 3, 31, tzinfo=ZoneInfo('Asia/Seoul'))
        self.assertEqual(nas.retention_cutoff(date).date(), datetime.date(2026, 3, 1))
        with self.assertRaises(ValueError):
            nas.quote('/backup\nrm file')


if __name__ == '__main__':
    import logging
    logging.disable(logging.CRITICAL)
    unittest.main()
