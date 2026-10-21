# 개발·운영 일일 백업

매일 04:00 Asia/Seoul에 `tools/backup.sh`를 실행한다. 서버 시스템 시간대도 Asia/Seoul이어야 한다.

- 저장 위치: `/home/whitehat/backups/expenditure/production/`, `development/`
- 보관: 최근 14일. 해당 환경의 새 백업 검증 성공 후에만 만료된 백업을 삭제한다.
- 로그: `/home/whitehat/backups/expenditure/backup.log`
- 백업: SQLite 스냅샷(data.sqlite, sessions.db), uploads 전체, .env, Compose, Dockerfile, package 파일, 이미지 ID와 코드 해시/커밋 정보.
- 각 환경의 컨테이너를 잠시 중지해 DB와 파일을 함께 백업하고, 실패 시에도 원래 실행 중인 컨테이너를 다시 시작한다. 원래 중지된 컨테이너는 그대로 둔다.
- 압축 전체를 읽어 검사하고 DB 무결성을 검증한 후에만 최종 파일명으로 확정한다.
- 파일은 소유자만 접근할 수 있다. DB·환경변수·첨부파일에는 비밀값과 개인정보가 있으므로 공개 저장소에 업로드하지 않는다.
- 수동 실행: `/home/whitehat/expenditure_dev/tools/backup.sh`
- 실패 시 로그에 FAILED와 오류 원인이 남고 종료 코드는 1이다. 외부 알림/서버 외부 복제는 별도 설정이 필요하다.

## 복구

1. 로그에서 SUCCESS를 확인한 백업을 고르고 소유자 전용 임시 디렉토리에 푼다.
2. `backup-info.json`의 이미지 ID/커밋과 코드 해시를 참고해 해당 버전의 코드를 준비한다. 이 일일 백업은 전체 소스나 Docker 이미지를 포함하지 않는다.
3. 대상 컨테이너를 중지하고 현재 DB·업로드·환경설정을 별도로 보관한다.
4. `db/`, `uploads/`, `.env`, `docker-compose.yml`을 해당 개발 또는 운영 프로젝트에 복원한다. 기존 DB의 WAL/SHM이 남아 복원 DB와 섞이지 않도록 DB 디렉토리 전체를 교체한다.
5. 환경별 포트/경로와 파일 권한을 확인하고 `docker compose up -d --build`로 시작한다.
6. 로그인·문서·첨부파일과 기동 로그를 확인한다.

동일 서버의 백업은 디스크 장애에 대비하지 못한다. 별도 장비에 암호화한 사본을 보관해야 한다.

## Synology NAS 복제

로컬 백업 종료 후 `tools/nas-upload.py`를 호출한다. NAS 실패가 로컬 백업 생성을 막지 않으며, 다음 실행에서 로컬에 남은 미전송 파일을 재시도한다.

- NAS: `192.168.118.250:54321`, SFTP 계정 `whitehat`
- 설정: `/home/whitehat/backups/expenditure/.nas/config.json` (Git 제외)
- 인증키: 같은 폴더의 `id_ed25519` / `id_ed25519.pub`. 개인키는 서버에만 보관한다.
- 호스트키: 기존 `/home/whitehat/.ssh/known_hosts`와 엄격하게 대조한다.
- 대상 경로: `/AegisAX_Backup/expenditure/{production,development}/`. `/AegisAX_Backup`은 인증 후 실제 SFTP 경로를 확인해야 한다.
- 전송 후 다시 내려받아 SHA-256을 대조한 뒤 `.partial` 파일을 최종 이름으로 변경한다.
- 업로드 이력과 NAS 파일 존재를 확인하여 중복 전송을 줄인다. 목적지가 바뀌면 다시 전송한다.
- 달력 기준 한 달 이전 파일은 해당 환경의 검증된 사본이 확인된 실행에서만 정리한다. 생성 규칙에 맞는 일일 백업 이름만 삭제하며 다른 NAS 파일은 건드리지 않는다.
- NAS 로그: `/home/whitehat/backups/expenditure/nas-upload.log`
- 인증 확인: `python3 tools/nas-upload.py --check`
- 인증·경로·최초 전송 검증 전에는 config의 `enabled`를 false로 유지한다. 검증 후 true로 바꾸고 `python3 tools/nas-upload.py`로 첫 전송을 수행한다.
- 전송 로직 테스트: `python3 -B -m unittest discover -s tests -p 'test_nas_upload.py'`

### NAS 공개키 등록

Synology DSM의 사용자 홈 서비스를 활성화하고 `whitehat` 계정의 홈 아래 `.ssh/authorized_keys`에 생성된 **공개키 한 줄**을 추가한다. 기존 authorized_keys를 덮어쓰지 않는다. 디렉토리 권한은 700, 키 파일은 600으로 설정하고 소유자는 whitehat으로 유지한다. SSH 셸을 이용한다면 NAS의 실제 SSH 서비스 포트를 사용한다(SFTP 포트와 다를 수 있다).

공식 안내: https://kb.synology.com/en-us/DSM/tutorial/How_to_log_in_to_DSM_with_key_pairs_as_admin_or_root_permission_via_SSH_on_computers
