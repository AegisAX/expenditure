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
const expenditureRoutes = require('./routes/expenditure');
const adminRoutes       = require('./routes/admin');

const app  = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
app.use(compression());

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
if (process.env.NODE_ENV === 'production') cspDirectives.upgradeInsecureRequests = [];

app.use(helmet({
    contentSecurityPolicy: { directives: cspDirectives },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
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
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        httpOnly: true,
        maxAge: 30 * 60 * 1000,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
}));

app.use(csrf());
app.use((req, res, next) => { res.locals.csrfToken = req.csrfToken(); next(); });

app.use('/', authRoutes);
app.use('/', requireLogin, expenditureRoutes);
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
    console.error(`[CSRF Error] ${req.ip} - ${req.originalUrl}`);
    res.status(403).json({ status: 'Error', msg: '보안 토큰이 만료되었거나 유효하지 않습니다.<br>페이지를 새로고침하세요.' });
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