#!/usr/bin/env python3
"""개발·운영 전자결재 데이터를 일관된 스냅샷으로 백업한다."""
import datetime
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
from zoneinfo import ZoneInfo

BASE = Path('/home/whitehat/backups/expenditure')
ENVIRONMENTS = [
    ('production', Path('/home/whitehat/expenditure'), 'expenditure-web-1'),
    ('development', Path('/home/whitehat/expenditure_dev'), 'expenditure_dev-web-1'),
]
KEEP_DAYS = 14


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def check_database(file):
    with sqlite3.connect(file.as_uri() + '?mode=ro', uri=True) as db:
        result = db.execute('PRAGMA quick_check').fetchall()
        if result != [('ok',)]:
            raise RuntimeError('SQLite integrity check failed')


def backup_environment(name, project, container):
    destination = BASE / name
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.datetime.now(ZoneInfo('Asia/Seoul')).strftime('%Y%m%d-%H%M%S-%f')
    archive_path = destination / (stamp + '.tar.gz')
    partial = destination / (stamp + '.partial')
    for required in ['db/data.sqlite', 'uploads', '.env', 'docker-compose.yml']:
        if not (project / required).exists():
            raise RuntimeError('Missing required backup source: ' + str(project / required))
    state = json.loads(command('docker', 'inspect', container))[0]
    was_running = state['State']['Running']
    logging.info('%s: backup started (container running=%s)', name, was_running)
    try:
        with tempfile.TemporaryDirectory(prefix='.stage-', dir=destination) as temp:
            stage = Path(temp)
            try:
                if was_running:
                    command('docker', 'stop', '--time', '30', container)
                # 중지된 DB에서 SQLite 백업 API로 WAL을 포함한 단일 스냅샷을 만든다.
                (stage / 'db').mkdir()
                for file in (project / 'db').iterdir():
                    if file.name not in ['data.sqlite', 'sessions.db']:
                        continue
                    with sqlite3.connect(file.as_uri() + '?mode=ro', uri=True) as src, sqlite3.connect(stage / 'db' / file.name) as dst:
                        src.backup(dst)
                metadata = {
                    'environment': name, 'created_at': datetime.datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
                    'project': str(project), 'container': container, 'image_id': state['Image'],
                    'git_commit': None, 'code_sha256': {},
                }
                if (project / '.git').exists():
                    metadata['git_commit'] = command('git', '-C', str(project), 'rev-parse', 'HEAD')
                for file in [project / 'server.js', project / 'database.js', project / 'package.json', project / 'package-lock.json', *project.glob('helpers/*.js'), *project.glob('middleware/*.js'), *project.glob('routes/*.js'), *project.glob('views/*.ejs'), *project.glob('public/**/*.js')]:
                    metadata['code_sha256'][str(file.relative_to(project))] = hashlib.sha256(file.read_bytes()).hexdigest()
                (stage / 'backup-info.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2))
                with tarfile.open(partial, 'w:gz') as archive:
                    archive.add(stage / 'db', arcname='db')
                    archive.add(stage / 'backup-info.json', arcname='backup-info.json')
                    for rel in ['uploads', '.env', 'docker-compose.yml', 'Dockerfile', 'package.json', 'package-lock.json']:
                        if (project / rel).exists():
                            archive.add(project / rel, arcname=rel)
            finally:
                # 실패하더라도 원래 실행 중이던 컨테이너는 반드시 재시작한다.
                if was_running:
                    command('docker', 'start', container)
                    if command('docker', 'inspect', '--format', '{{.State.Running}}', container) != 'true':
                        raise RuntimeError('Container restart failed: ' + container)
            # 전체 압축 스트림과 필수 항목 확인. 검증은 서비스 재시작 후 수행한다.
            with tarfile.open(partial, 'r:gz') as archive:
                names = set()
                for member in archive:
                    names.add(member.name)
                    if member.isfile():
                        stream = archive.extractfile(member)
                        while stream.read(1024 * 1024):
                            pass
                if not {'db/data.sqlite', '.env', 'docker-compose.yml', 'backup-info.json'} <= names:
                    raise RuntimeError('Required archive members missing')
            for file in (stage / 'db').iterdir():
                check_database(file)
            partial.replace(archive_path)
        logging.info('%s: SUCCESS %s (%d bytes)', name, archive_path, archive_path.stat().st_size)
        # 해당 환경의 새 백업 성공 후에만 보관 기간이 지난 일일 백업 삭제.
        cutoff = datetime.datetime.now(ZoneInfo('Asia/Seoul')) - datetime.timedelta(days=KEEP_DAYS)
        for old in destination.glob('*.tar.gz'):
            try:
                created = datetime.datetime.strptime(old.name.split('.')[0], '%Y%m%d-%H%M%S-%f').replace(tzinfo=ZoneInfo('Asia/Seoul'))
            except ValueError:
                continue
            if created < cutoff:
                old.unlink()
                logging.info('%s: expired backup removed: %s', name, old.name)
    finally:
        partial.unlink(missing_ok=True)


def main():
    os.umask(0o077)
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s', handlers=[logging.FileHandler(BASE / 'backup.log'), logging.StreamHandler()])
    with (BASE / '.backup.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            logging.error('Another backup is running')
            return 1
        failed = False
        for args in ENVIRONMENTS:
            try:
                backup_environment(*args)
            except Exception:
                logging.exception('%s: FAILED', args[0])
                failed = True
        # 로컬 백업 실패 여부와 별개로 남아 있는 미전송 백업을 재시도한다.
        # NAS 실패가 로컬 백업 생성·검증·보관 처리를 막지 않는다.
        uploader = Path(__file__).with_name('nas-upload.py')
        if uploader.exists():
            try:
                result = subprocess.run(['/usr/bin/python3', str(uploader)], check=False)
                if result.returncode:
                    logging.error('NAS transfer failed; local backup results retained')
                    failed = True
            except Exception:
                logging.exception('NAS transfer could not start; local backups retained')
                failed = True
        return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
