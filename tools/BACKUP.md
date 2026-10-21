# 독립 전체 백업 (development)

이 프로젝트의 tools/backup.sh만 실행하면 전체 소스·설정·DB 백업과 NAS 전송을 수행한다. 다른 프로젝트 디렉토리나 스크립트를 참조하지 않는다.

## 실행과 설정

- 예약: 매일 04:10 KST. 서버 cron 시간대는 Asia/Seoul이다.
- 수동 실행: 프로젝트 디렉토리에서 `./tools/backup.sh`.
- 로컬 설정: `.backup/config.json`. Git에는 `tools/backup.example.json`만 보관한다.
- 프로젝트 경로는 스크립트 위치로 자동 계산한다. Docker 컨테이너는 현재 프로젝트의 Compose 서비스(web)에서 찾아 고정 컨테이너명을 사용하지 않는다.
- 기본 보관 위치: 프로젝트 기준 `../backups/expenditure/development`. config의 backup_dir로 변경할 수 있다.
- 로컬 보관: 7일. 새 백업 검증 성공 후에만 해당 프로젝트의 만료 백업을 삭제한다.
- NAS: `/AegisAX_Backup/expenditure/development`, 30일 보관.
- 로그: 로컬 백업 디렉토리의 backup.log, nas-upload.log, cron.log.
- 프로젝트별 `.backup/backup.lock`, upload.lock으로 중복 실행을 막는다.

## 백업 내용

- `source/`: 실제 프로젝트 소스 전체. Git 추적 여부와 관계없이 파일을 복사하고 SHA-256 목록을 기록한다.
- `.git`, node_modules, 캐시, 로컬 에이전트 상태 및 `.backup/`는 source에서 제외한다.
- `db/`: data.sqlite, sessions.db의 SQLite 백업 API 스냅샷(WAL 반영).
- 전자결재의 uploads/는 별도 영역에 포함한다. moiso는 별도 업로드 볼륨을 사용하지 않는다.
- `.env`, docker-compose.yml, Dockerfile, package 파일, backup-info.json, backup-config.json도 포함한다.
- 백업을 만드는 동안 이 프로젝트의 컨테이너만 잠시 중지하고, 실패 시에도 원래 실행 중이었다면 다시 시작한다.
- 압축 전체·소스 해시·DB 무결성 검증 후에만 최종 백업 파일로 확정한다.
- NAS 전송은 .partial로 올린 후 다시 내려받아 SHA-256을 검사하고 최종 파일명으로 변경한다.
- 전송에 실패해도 로컬 백업은 남는다. 다음 실행에서 남은 미전송 파일을 재시도한다.
- 기존 구형 백업은 그대로 유지한다. source/가 없는 구형 백업은 별도 소스가 필요하다.

## 인증정보

NAS 인증은 이 프로젝트의 `.backup/id_ed25519`, id_ed25519.pub, known_hosts를 사용한다. 다른 프로젝트의 인증정보를 참조하지 않는다. 키의 사본을 분리 배치했으며 NAS 공개키 등록을 새로 할 필요는 없다.

`.backup/`는 Git·Docker 빌드·소스 백업에서 제외한다. 디렉토리는 700, 개인키·실제 설정·전송 이력은 600으로 관리한다. 인증키는 백업에 포함하지 않으며 별도의 안전한 방법으로 서버 이전 시 옮기거나 새 키를 발급해야 한다.

- 연결 확인: `python3 tools/nas-upload.py --check`
- 전송만 재시도: `python3 tools/nas-upload.py`

## 복구 및 서버 이전

1. 접근 제한된 임시 공간에 검증된 최신 백업을 푼다.
2. 빈 프로젝트 디렉토리에 source/ 내용을 복원한다. GitHub 없이 앱 소스를 복원할 수 있다.
3. 대상 컨테이너를 중지하고 현재 데이터를 별도로 보관한 뒤 db/와 uploads/(있는 경우), 루트 .env·Compose를 복원한다. 기존 DB의 WAL/SHM과 섞지 않는다.
4. `.backup/`를 권한 700으로 만들고 backup-config.json을 `.backup/config.json`으로 복원한다. 또는 tools/backup.example.json에서 새로 설정한다.
5. 개인키·known_hosts를 안전하게 옮기거나 새로 등록한다. 서버가 달라지면 환경설정·포트·backup_dir·NAS 접근을 확인한다. 상대 경로 설정이므로 기존 서버 홈 경로에 의존하지 않는다.
6. Docker/Compose, Python 3.9 이상, OpenSSH SFTP와 Asia/Seoul 시간대를 준비한다.
7. `docker compose up -d --build`로 시작하고 로그인·상태를 확인한다. Docker 이미지·node_modules는 포함하지 않으므로 베이스 이미지 및 npm 저장소 접근은 필요하다.
8. 이 프로젝트의 tools/backup.sh 경로만 cron에 등록한다. cron 자체는 소스 파일이 아니므로 새 서버에 재등록해야 한다.
9. 수동 백업·NAS 검증 후 예약 실행을 확인한다.

자동 테스트: `python3 -B -m unittest discover -s tests -p 'test_*backup*.py'`와 `python3 -B -m unittest discover -s tests -p 'test_nas_upload.py'`.
