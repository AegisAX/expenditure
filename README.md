# 금오공고 총동문회 전자결재시스템

전자결재 신청·승인·서명 기능을 제공하는 웹 애플리케이션입니다.  
Node.js + Express + SQLite3 기반으로 동작하며, Docker를 통해 손쉽게 배포할 수 있습니다.

---

## 요구 사항

| 항목 | 버전 |
|------|------|
| Node.js | 18 이상 |
| npm | 9 이상 |
| Docker & Docker Compose | 선택 사항 (Docker 배포 시 필요) |

---

## 시작하기

### 1. 저장소 클론

```bash
git clone <저장소 URL>
cd expenditure
```

### 2. 환경변수 파일 설정

프로젝트 루트에 있는 `.env.example`을 복사하여 `.env` 파일을 생성합니다.

```bash
cp .env.example .env
```

`.env` 파일을 열어 아래 항목을 실제 값으로 채웁니다.

```ini
# 세션 암호화 키 — 무작위 긴 문자열로 설정하세요.
# 생성 예시: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
SESSION_SECRET=여기에_무작위_문자열_입력

# 이메일 발송 설정 (Gmail 사용 시 앱 비밀번호 사용 권장)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
```

> **주의:** `.env` 파일은 `.gitignore`에 등록되어 있으므로 절대 커밋되지 않습니다.  
> 절대 외부에 공유하지 마세요.

---

## 실행 방법

### A. 로컬 직접 실행 (개발·테스트용)

```bash
# 의존성 설치
npm install

# 서버 시작
npm start
```

브라우저에서 `http://localhost:3000` 으로 접속합니다.

---

### B. Docker로 실행 (운영 환경 권장)

```bash
# 이미지 빌드 및 컨테이너 시작
docker compose up -d --build
```

브라우저에서 `http://localhost:8081` 으로 접속합니다.

컨테이너를 중지하려면:

```bash
docker compose down
```

> **데이터 저장 위치:** DB 파일과 첨부파일은 호스트의 `./db`, `./uploads` 디렉토리에 마운트되어 컨테이너를 재시작해도 유지됩니다.

---

## 초기 관리자 계정

서버를 **최초 실행**하면 관리자 계정이 자동으로 생성되고,  
서버 콘솔(또는 Docker 로그)에 아래와 같이 초기 비밀번호가 출력됩니다.

```
================================================================
🚨 [Security Notice] 관리자 계정이 초기 생성되었습니다.
👉 ID : admin@localhost
👉 PW : 3f9a1bc2d4e5f678
⚠️  보안을 위해 최초 로그인 후 [정보 수정]에서 반드시 비밀번호를 변경하세요.
================================================================
```

Docker 환경에서 로그를 확인하는 방법:

```bash
docker compose logs web
```

> 초기 비밀번호는 로그에 **한 번만** 출력됩니다. 반드시 메모해 두거나 즉시 로그인하여 변경하세요.

---

## 프로젝트 구조

```
.
├── server.js              # 앱 설정 및 라우트 마운트
├── database.js            # DB 초기화 및 테이블 정의
│
├── helpers/               # 공통 유틸리티
│   ├── db.js              # DB 헬퍼 함수 (채번, 락, 감사로그 등)
│   ├── email.js           # 이메일 발송 및 HTML 생성
│   └── file.js            # 파일 업로드·저장 (Multer 설정 포함)
│
├── middleware/            # Express 미들웨어
│   ├── auth.js            # 로그인·관리자 권한 체크
│   └── validators.js      # 입력값 검증 규칙 및 Rate Limiter
│
├── routes/                # 라우트 핸들러
│   ├── auth.js            # 로그인, 회원가입, 로그아웃
│   ├── expenditure.js     # 문서 조회·제출·결재·잠금·첨부파일
│   └── admin.js           # 관리자 전용 API
│
├── views/                 # EJS 템플릿
├── public/                # 정적 파일 (아이콘, PWA 리소스)
├── db/                    # SQLite DB 파일 (gitignore)
├── uploads/               # 업로드 파일 (gitignore)
├── Dockerfile
├── docker-compose.yml
├── .env.example           # 환경변수 템플릿
└── .env                   # 실제 환경변수 (gitignore — 직접 생성 필요)
```

---

## 라이선스

[LICENSE](./LICENSE) 파일을 참고하세요.