#!/usr/bin/env python3
"""검증된 로컬 일일 백업을 SFTP로 복제. 비밀 설정은 저장소 밖에 보관."""
import argparse
import datetime
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import tempfile
from zoneinfo import ZoneInfo

PROJECT = Path(__file__).resolve().parents[1]
PRIVATE = PROJECT / '.backup'
CONFIG = PRIVATE / 'config.json'
BACKUP_NAME = re.compile(r'^\d{8}-\d{6}-\d{6}\.tar\.gz$')


def quote(value):
    if any(c in str(value) for c in '\r\n\x00'):
        raise ValueError('Invalid SFTP path')
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def retention_cutoff(now, keep_days=30):
    return now - datetime.timedelta(days=keep_days)


class SFTP:
    def __init__(self, config):
        self.config = config
        self.destination = config['user'] + '@' + config['host']
        if not re.fullmatch(r'[\w.-]+@[\w.:-]+', self.destination):
            raise ValueError('Invalid NAS destination')

    def run(self, commands):
        c = self.config
        result = subprocess.run([
            '/usr/bin/sftp', '-oBatchMode=yes', '-oIdentitiesOnly=yes',
            '-oStrictHostKeyChecking=yes', '-oConnectTimeout=10',
            '-oServerAliveInterval=15', '-oServerAliveCountMax=3',
            '-oUserKnownHostsFile=' + c['known_hosts'],
            '-i', c['identity_file'], '-P', str(c['port']), '-b', '-', self.destination,
        ], input='\n'.join(commands) + '\n', text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=600)
        if result.returncode:
            raise RuntimeError('SFTP failed: ' + result.stdout[-2000:])
        return result.stdout

    def directory(self, environment):
        # NAS 기존 공유 폴더 자체는 생성하지 않는다. 경로를 명시적으로 확인한다.
        project = self.config['remote_project']
        folder = self.config['remote_environment']
        if not all(re.fullmatch(r'[a-z][a-z0-9_-]*', name) for name in [project, folder]):
            raise ValueError('Invalid remote backup folder')
        return ['cd ' + quote(self.config['remote_root']), '-mkdir ' + project,
                'cd ' + project, '-mkdir ' + folder, 'cd ' + folder]

    def listing(self, environment):
        text = self.run(self.directory(environment) + ['ls -1'])
        return {line.strip() for line in text.splitlines() if BACKUP_NAME.fullmatch(line.strip())}


def upload(config, sftp):
    state_path = PRIVATE / 'uploaded.json'
    receipts = json.loads(state_path.read_text()) if state_path.exists() else {}
    failed = False
    for environment in [config['environment']]:
        try:
            remote = sftp.listing(environment)
            local_dir = Path(config['local_dir'])
            local = sorted(local_dir.glob('*.tar.gz'))
            if not local:
                raise RuntimeError('No local backup: ' + environment)
            verified = False
            for path in local:
                if not BACKUP_NAME.fullmatch(path.name):
                    continue
                digest = sha256(path)
                receipt_key = environment + '/' + path.name
                # NAS 목적지 변경 시 이전 전송 이력을 재사용하지 않는다.
                destination = config['host'] + ':' + str(config['port']) + ':' + config['user'] + ':' + config['remote_root'] + ':' + json.dumps({'remote_project': config['remote_project'], 'remote_environment': config['remote_environment']}, sort_keys=True)
                if path.name in remote and receipts.get(receipt_key) == {'sha256': digest, 'destination': destination}:
                    verified = True
                    continue
                commands = sftp.directory(environment)
                partial = path.name + '.partial'
                with tempfile.TemporaryDirectory(prefix='nas-verify-', dir=PRIVATE) as temp:
                    downloaded = Path(temp) / path.name
                    # 전송 중 파일은 .partial. 내려받아 SHA-256 확인 후에만 최종 이름으로 확정.
                    sftp.run(commands + ['put ' + quote(path) + ' ' + quote(partial),
                                        'chmod 600 ' + quote(partial),
                                        'get ' + quote(partial) + ' ' + quote(downloaded)])
                    if sha256(downloaded) != digest:
                        raise RuntimeError('NAS read-back hash mismatch: ' + receipt_key)
                    sftp.run(commands + ['rename ' + quote(partial) + ' ' + quote(path.name)])
                receipts[receipt_key] = {'sha256': digest, 'destination': destination}
                temporary = state_path.with_suffix('.tmp')
                temporary.write_text(json.dumps(receipts, indent=2))
                temporary.replace(state_path)
                verified = True
                logging.info('NAS SUCCESS: %s SHA-256 verified', receipt_key)
            # 해당 환경의 검증된 사본을 확인한 실행에서만 30일 보관 기간이 지난 백업 삭제.
            if verified:
                cutoff = retention_cutoff(datetime.datetime.now(ZoneInfo('Asia/Seoul')), config.get('keep_days', 30))
                for filename in sorted(remote):
                    created = datetime.datetime.strptime(filename[:-7], '%Y%m%d-%H%M%S-%f').replace(tzinfo=ZoneInfo('Asia/Seoul'))
                    if created < cutoff:
                        sftp.run(sftp.directory(environment) + ['rm ' + quote(filename)])
                        logging.info('NAS retention: removed %s/%s', environment, filename)
        except Exception:
            failed = True
            logging.exception('NAS FAILED: %s (local backups preserved)', environment)
    return int(failed)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--config', type=Path, default=CONFIG)
    args = parser.parse_args()
    settings = json.loads(args.config.read_text())
    destination = (PROJECT / settings['backup_dir']).resolve()
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s',
                        handlers=[logging.FileHandler(destination / 'nas-upload.log'), logging.StreamHandler()])
    config = dict(settings['nas'])
    config['environment'] = settings['environment']
    config['local_dir'] = str(destination)
    for key in ['identity_file', 'known_hosts']:
        config[key] = str((PROJECT / config[key]).resolve())
    if not config.get('enabled') and not args.check:
        logging.warning('NAS upload disabled for this project')
        return 0
    with (PRIVATE / 'upload.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            logging.error('NAS upload already running for this project')
            return 1
        try:
            sftp = SFTP(config)
            if args.check:
                output = sftp.run(['pwd', 'cd ' + quote(config['remote_root']), 'pwd'])
                logging.info('NAS authentication and remote directory OK: %s', output.strip())
                return 0
            return upload(config, sftp)
        except Exception:
            logging.exception('NAS connection failed; local backups preserved')
            return 1


if __name__ == '__main__':
    raise SystemExit(main())
