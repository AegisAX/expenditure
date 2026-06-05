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
    // [수정] csurf 가 GET /login 응답 시 req.session._csrf 에 secret 을 저장하지만,
    //   resave:false + saveUninitialized:false 조합에서는 SQLite store 가 이를
    //   영속화하지 않아 다음 POST 요청에서 session._csrf 가 NO 로 잡히고
    //   CSRF mismatch 가 발생하는 사례가 확인됐다.
    //   안전을 위해 두 옵션을 모두 활성화 — SQLite store 쓰기 부하는 미미.
    resave: true,
    saveUninitialized: true,
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

app.use(csrf());
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
    // [주의] 이전에 추가했던 req.session.save 명시 호출은 SQLite store 의 동시 write 와
    //   충돌해 모든 GET 요청이 hang 되는 사례가 확인되어 제거.
    //   대신 session 옵션 resave:true + saveUninitialized:true 로 영속화를 보장한다.
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
    //   - sessionID 가 매 요청마다 바뀌면 → 쿠키가 유지 안 되는 것 (HTTPS·proxy 환경 문제 의심)
    //   - clientToken / sessionSecret 둘 다 있는데 mismatch 면 → 토큰 발급/사용 사이클 문제
    const hdrToken    = req.headers['csrf-token'] || req.headers['x-csrf-token'];
    const bodyToken   = (req.body && req.body._csrf) ? '(body)' : '';
    const cookieSid   = req.headers.cookie && req.headers.cookie.includes('connect.sid') ? 'YES' : 'NO';
    const sessionId   = req.sessionID || '(none)';
    const sessionHas  = req.session && req.session._csrf ? 'YES' : 'NO';
    console.error(
        `[CSRF Error] ${req.ip} - ${req.method} ${req.originalUrl}\n` +
        `   sessionID=${sessionId}  session._csrf?=${sessionHas}  cookie.connect.sid?=${cookieSid}\n` +
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