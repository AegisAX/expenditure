import importlib.util
from pathlib import Path
import hashlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('backup', Path(__file__).resolve().parents[1] / 'tools/backup.py')
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class SourceBackupTests(unittest.TestCase):
    def test_complete_source_includes_untracked_and_hidden_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / 'project'
            project.mkdir()
            files = ['server.js', 'database.js', 'package.json', 'package-lock.json', 'Dockerfile', 'docker-compose.yml', '.env', 'routes/new.js', 'public/vendor/editor.js', 'views/test.ejs', 'tools/backup.sh', 'docs/restore.md', '.github/workflows/check.yml', '.env.example']
            for name in files:
                file = project / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('content:' + name)
            for name in ['node_modules/pkg/index.js', '.git/config', 'db/data.sqlite', 'uploads/file.pdf', 'tools/__pycache__/module.pyc', '.backup/id_ed25519', '.backup/config.json']:
                file = project / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('excluded')
            manifest = backup.snapshot_source(project, root / 'snapshot')
            self.assertEqual(set(manifest), set(files))
            for name in files:
                self.assertEqual((root / 'snapshot' / name).read_bytes(), (project / name).read_bytes())
                self.assertEqual(manifest[name], hashlib.sha256((project / name).read_bytes()).hexdigest())

    def test_missing_required_source_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'project').mkdir()
            with self.assertRaisesRegex(RuntimeError, 'Source snapshot missing'):
                backup.snapshot_source(root / 'project', root / 'snapshot')


if __name__ == '__main__':
    unittest.main()
