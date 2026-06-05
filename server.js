require('dotenv').config();

const express    = require('express');
const session    = require('express-session');
const compression = require('compression');
const path       = require('path');
const cookieParser = require('cookie-parser');
const csrf       = require('csurf');
const helmet     = require('helmet');
const SQLiteStore = require('connect-sqlite3')(session);

const { checkAndMigrateDB, clearStaleLocks } = require('./helpers/db');
const { initTransporter } = require('./helpers/email');
const { requireLogin } = require('./middleware/auth');
const authRoutes        = require('./routes/auth');
const approvalRoutes = require('./routes/approval');
const adminRoutes       = require('./routes/admin');

const app  = express();
const PORT = process.env.PORT || 3000;

// 리버스 프록시 뒤에 있을 때 X-Forwarded-* 헤더를 신뢰
app.set('trust proxy', 1);
app.use(compression());

// HTTPS 강제 관련 헤더(upgrade-insecure-requests, HSTS) 활성화 여부.
// 모든 트래픽이 HTTPS인 환경에서만 true. 로컬 IP HTTP 접속을 함께 허용하려면 false.
const HTTPS_ENFORCE = process.env.HTTPS_ENFORCE === 'true';

const cspDirectives = {
    defaultSrc:  ["'self'"],
    scriptSrc:   ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
    scriptSrcAttr: ["'unsafe-inline'"],
    styleSrc:    ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
    imgSrc:      ["'self'", "data:", "blob:"],
    connectSrc:  ["'self'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
    fontSrc:     ["'self'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
    objectSrc:   ["'none'"],
};

// HTTPS 강제면 추가, 아니면 helmet 기본값을 명시적으로 제거
if (HTTPS_ENFORCE) {
    cspDirectives.upgradeInsecureRequests = [];
} else {
    cspDirectives.upgradeInsecureRequests = null;   // ← 기본값 무력화
}

app.use(helmet({
    contentSecurityPolicy: { directives: cspDirectives },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
    hsts: HTTPS_ENFORCE ? undefined : false   // HTTP 접속도 허용하려면 HSTS 끔
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

app.use(session({
    store: new SQLiteStore({ db: 'sessions.db', dir: './db', concurrentDB: true }),
    secret: process.env.SESSION_SECRET || 'secret-key-replace-me',
    // [수정] csurf 를 쿠키 기반으로 전환 (위) 후 세션 의존이 사라졌으므로
    //   세션 옵션을 보수적 기본값으로 복원.
    //   이전에 두 옵션을 true 로 바꿨더니 SQLite 동시 write race 영향으로
    //   세션 ID 가 매 요청마다 갱신되며 로그인 정보가 잠시 후 유실되는 사례 확인.
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        httpOnly: true,
        maxAge: 30 * 60 * 1000,
        // [수정] secure 를 명시적 boolean 으로.
        //   'auto' 는 trust proxy + X-Forwarded-Proto 가 정확해야만 잘 동작하는데,
        //   사내 reverse proxy 환경에서 헤더가 누락되면 secure=true 인 쿠키가 발급되어
        //   브라우저가 쿠키를 무시 → 매 요청 새 세션 → CSRF mismatch 가 끊임없이 발생.
        //   HTTPS 강제 환경에서만 true 로 두고, 그 외엔 false.
        secure: process.env.HTTPS_ENFORCE === 'true',
        sameSite: 'lax'
    }
}));

// [CSRF] 쿠키 기반 csurf 사용.
//   기존 세션 기반(default)에서는 GET 응답 시 csurf 가 req.session._csrf 에 secret 을 set 하지만
//   SQLite session store 와의 race / saveUninitialized 조합 사정으로 secret 이 영속화되지 않아
//   다음 POST 요청에서 session._csrf?=NO 로 잡히고 CSRF mismatch 가 반복 발생하는 사례가 있었다.
//   쿠키 기반은 secret 을 별도 httpOnly 쿠키 '_csrf' 에 즉시 저장하므로
//   세션 의존성·SQLite write race 가 없다.
app.use(csrf({
    cookie: {
        key: '_csrf',
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.HTTPS_ENFORCE === 'true'
    }
}));
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});

app.use('/', authRoutes);
app.use('/', requireLogin, approvalRoutes);
app.use('/', requireLogin, adminRoutes);

// /api/* 는 404 JSON 으로 분리, 나머지만 /login 으로 리다이렉트
app.use('/api', (req, res) => {
    res.status(404).json({
        status: 'Error',
        msg: 'API 경로를 찾을 수 없습니다.',
        path: req.originalUrl
    });
});
app.use((req, res) => res.redirect('/login'));

app.use((err, req, res, next) => {
    if (err.code !== 'EBADCSRFTOKEN') return next(err);
    // [진단] CSRF mismatch 원인 파악용 상세 로그.
    //   쿠키 기반 csurf 사용 — 서버는 '_csrf' 쿠키의 secret 과 클라이언트 헤더 토큰을 검증한다.
    //   csrf.cookie?=YES 인데 mismatch 면 → 클라이언트가 옛 토큰을 보내거나 쿠키 도메인 불일치
    //   csrf.cookie?=NO  이면 → 클라이언트가 쿠키를 안 보낸 것 (samesite/secure/proxy 의심)
    const cookieHeader = req.headers.cookie || '';
    const hdrToken     = req.headers['csrf-token'] || req.headers['x-csrf-token'];
    const bodyToken    = (req.body && req.body._csrf) ? '(body)' : '';
    const cookieSid    = cookieHeader.includes('connect.sid') ? 'YES' : 'NO';
    const csrfCookie   = cookieHeader.includes('_csrf=') ? 'YES' : 'NO';
    const sessionId    = req.sessionID || '(none)';
    console.error(
        `[CSRF Error] ${req.ip} - ${req.method} ${req.originalUrl}\n` +
        `   sessionID=${sessionId}  cookie.connect.sid?=${cookieSid}  cookie._csrf?=${csrfCookie}\n` +
        `   client header token=${hdrToken ? 'present(' + String(hdrToken).slice(0,8) + '...)' : 'MISSING'}  ${bodyToken}\n` +
        `   X-Forwarded-Proto=${req.headers['x-forwarded-proto'] || '(none)'}  Host=${req.headers.host}`
    );
    res.status(403).json({
        status: 'Error',
        code: 'CSRF_INVALID',
        msg: '보안 토큰이 만료되었거나 유효하지 않습니다.<br>페이지를 새로고침하세요.'
    });
});

setTimeout(checkAndMigrateDB, 1000);
setInterval(clearStaleLocks, 10 * 60 * 1000);

// [A-2] 기동 시 DB 에서 SMTP 설정을 읽어 transporter 초기화.
// settings 테이블이 준비된 후 실행되도록 checkAndMigrateDB(1초 지연) 이후 타이밍에 맞춰 호출한다.
// 실패하더라도 서버 자체는 계속 기동된다 (메일만 비활성).
setTimeout(() => {
    initTransporter().catch(e => console.error('[Mail Error] init:', e.message));
}, 1500);

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);

    // [추가] SMTP 설정 누락 경고
    const smtpRequired = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS'];
    const smtpMissing  = smtpRequired.filter(key => !process.env[key]);
    if (smtpMissing.length > 0) {
        console.warn('⚠️  [Mail Warning] 다음 SMTP 환경변수가 설정되지 않아 이메일 알림이 발송되지 않습니다:');
        console.warn(`    누락 항목: ${smtpMissing.join(', ')}`);
        console.warn('    .env 파일에서 SMTP 설정을 확인해주세요.');
    }

    // [추가] SESSION_SECRET 기본값 사용 경고
    if (!process.env.SESSION_SECRET) {
        console.warn('⚠️  [Security Warning] SESSION_SECRET이 설정되지 않았습니다.');
        console.warn('    기본값(secret-key-replace-me)이 사용 중입니다. 반드시 .env에서 변경하세요.');
    }
});