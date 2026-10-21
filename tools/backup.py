#!/usr/bin/env python3
"""현재 프로젝트의 전체 소스·설정·DB를 일관된 스냅샷으로 백업한다."""
import argparse
import datetime
import fcntl
import hashlib
import json
import logging
import os
import re
import shutil
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
from zoneinfo import ZoneInfo

PROJECT = Path(__file__).resolve().parents[1]
CONFIG = PROJECT / '.backup' / 'config.json'
# 프로젝트 데이터는 별도 DB 스냅샷/첨부 영역으로 보관. 의존성은 lock 파일로 재설치한다.
SOURCE_EXCLUDED = {'.git', 'node_modules', 'db', 'uploads', '.cache', '__pycache__', '.claude', '.codex', '.backup'}


def snapshot_source(project, destination):
    def ignore(directory, names):
        excluded = {name for name in names if name in {'node_modules', '__pycache__', '.cache'}}
        if Path(directory) == project:
            excluded.update(SOURCE_EXCLUDED.intersection(names))
        return excluded
    shutil.copytree(project, destination, ignore=ignore, symlinks=True)
    hashes = {}
    for file in sorted(destination.rglob('*')):
        if file.is_file() and not file.is_symlink():
            hashes[str(file.relative_to(destination))] = hashlib.sha256(file.read_bytes()).hexdigest()
    for required in ['server.js', 'database.js', 'package.json', 'package-lock.json', 'Dockerfile', 'docker-compose.yml', '.env']:
        if required not in hashes:
            raise RuntimeError('Source snapshot missing: ' + required)
    return hashes


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def check_database(file):
    with sqlite3.connect(file.as_uri() + '?mode=ro', uri=True) as db:
        result = db.execute('PRAGMA quick_check').fetchall()
        if result != [('ok',)]:
            raise RuntimeError('SQLite integrity check failed')


def backup_environment(name, project, container, job):
    destination = job['destination']
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.datetime.now(ZoneInfo('Asia/Seoul')).strftime('%Y%m%d-%H%M%S-%f')
    archive_path = destination / (stamp + '.tar.gz')
    partial = destination / (stamp + '.partial')
    required_sources = ['db/' + job['databases'][0], '.env', 'docker-compose.yml']
    if job['uploads']:
        required_sources.append('uploads')
    for required in required_sources:
        if not (project / required).exists():
            raise RuntimeError('Missing required backup source: ' + str(project / required))
    state = json.loads(command('docker', 'inspect', container))[0]
    was_running = state['State']['Running']
    logging.info('%s: backup started (container running=%s)', name, was_running)
    try:
        with tempfile.TemporaryDirectory(prefix='.stage-', dir=destination) as temp:
            stage = Path(temp)
            source_hashes = snapshot_source(project, stage / 'source')
            try:
                if was_running:
                    command('docker', 'stop', '--time', '30', container)
                # 중지된 DB에서 SQLite 백업 API로 WAL을 포함한 단일 스냅샷을 만든다.
                (stage / 'db').mkdir()
                for file in (project / 'db').iterdir():
                    if file.name not in job['databases']:
                        continue
                    with sqlite3.connect(file.as_uri() + '?mode=ro', uri=True) as src, sqlite3.connect(stage / 'db' / file.name) as dst:
                        src.backup(dst)
                metadata = {
                    'environment': name, 'created_at': datetime.datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
                    'project': str(project), 'container': container, 'image_id': state['Image'],
                    'git_commit': None, 'code_sha256': {}, 'format_version': 2,
                    'source_sha256': source_hashes, 'source_excluded': sorted(SOURCE_EXCLUDED),
                }
                if (project / '.git').exists():
                    metadata['git_commit'] = command('git', '-C', str(project), 'rev-parse', 'HEAD')
                for file in [project / 'server.js', project / 'database.js', project / 'package.json', project / 'package-lock.json', *project.glob('helpers/*.js'), *project.glob('middleware/*.js'), *project.glob('routes/*.js'), *project.glob('views/*.ejs'), *project.glob('public/**/*.js')]:
                    metadata['code_sha256'][str(file.relative_to(project))] = hashlib.sha256(file.read_bytes()).hexdigest()
                (stage / 'backup-config.json').write_text(json.dumps(job['settings'], ensure_ascii=False, indent=2))
                (stage / 'backup-info.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2))
                with tarfile.open(partial, 'w:gz') as archive:
                    archive.add(stage / 'source', arcname='source')
                    archive.add(stage / 'db', arcname='db')
                    archive.add(stage / 'backup-info.json', arcname='backup-info.json')
                    archive.add(stage / 'backup-config.json', arcname='backup-config.json')
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
                verified_sources = set()
                for member in archive:
                    names.add(member.name)
                    if member.isfile():
                        stream = archive.extractfile(member)
                        digest = hashlib.sha256()
                        while chunk := stream.read(1024 * 1024):
                            digest.update(chunk)
                        if member.name.startswith('source/'):
                            relative = member.name[len('source/'):]
                            if source_hashes.get(relative) != digest.hexdigest():
                                raise RuntimeError('Source archive hash mismatch: ' + relative)
                            verified_sources.add(relative)
                if not {'db/' + job['databases'][0], '.env', 'docker-compose.yml', 'backup-info.json', 'source/server.js', 'source/package-lock.json'} <= names:
                    raise RuntimeError('Required archive members missing')
                if verified_sources != set(source_hashes):
                    raise RuntimeError('Source archive files missing')
            for file in (stage / 'db').iterdir():
                check_database(file)
            partial.replace(archive_path)
        if job.get('health_marker'):
            marker = project / job['health_marker']
            marker.write_text(datetime.datetime.now(ZoneInfo('Asia/Seoul')).isoformat())
        logging.info('%s: SUCCESS %s (%d bytes)', name, archive_path, archive_path.stat().st_size)
        # 해당 환경의 새 백업 성공 후에만 보관 기간이 지난 일일 백업 삭제.
        cutoff = datetime.datetime.now(ZoneInfo('Asia/Seoul')) - datetime.timedelta(days=job['keep_days'])
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



def prune_legacy_db_backups(directory, keep_days):
    cutoff = datetime.datetime.now(ZoneInfo('Asia/Seoul')) - datetime.timedelta(days=keep_days)
    for file in directory.glob('moiso-*.sqlite.gz'):
        match = re.fullmatch(r'moiso-(\d{8}-\d{4})\.sqlite\.gz', file.name)
        if match and file.is_file():
            created = datetime.datetime.strptime(match[1], '%Y%m%d-%H%M').replace(tzinfo=ZoneInfo('Asia/Seoul'))
            if created < cutoff:
                file.unlink()
                logging.info('Expired legacy DB backup removed: %s', file.name)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, default=CONFIG)
    args = parser.parse_args()
    settings = json.loads(args.config.read_text())
    destination = (PROJECT / settings['backup_dir']).resolve()
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    private = PROJECT / '.backup'
    private.mkdir(mode=0o700, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s',
                        handlers=[logging.FileHandler(destination / 'backup.log'), logging.StreamHandler()])
    with (private / 'backup.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            logging.error('Another backup is running for this project')
            return 1
        failed = False
        try:
            container = command('docker', 'compose', '--project-directory', str(PROJECT),
                                '-f', str(PROJECT / 'docker-compose.yml'), 'ps', '-aq', settings.get('service', 'web'))
            if not container or len(container.splitlines()) != 1:
                raise RuntimeError('Expected one Compose service container')
            job = {**settings, 'destination': destination, 'settings': settings}
            backup_environment(settings['environment'], PROJECT, container, job)
            if settings.get('legacy_db_backup_dir'):
                prune_legacy_db_backups((PROJECT / settings['legacy_db_backup_dir']).resolve(), settings['keep_days'])
        except Exception:
            logging.exception('Local full backup FAILED')
            failed = True
        # NAS는 자기 프로젝트의 설정·인증키·이력만 사용한다.
        try:
            uploader = Path(__file__).with_name('nas-upload.py')
            result = subprocess.run(['/usr/bin/python3', str(uploader), '--config', str(args.config)], check=False)
            if result.returncode:
                logging.error('NAS transfer failed; local backups retained')
                failed = True
        except Exception:
            logging.exception('NAS transfer could not start; local backups retained')
            failed = True
        return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
