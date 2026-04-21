// [추가] 환경변수 로드 (최상단에 위치해야 함)
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const compression = require('compression');
const path = require('path');
const fs = require('fs'); 
const bcrypt = require('bcryptjs'); 
const nodemailer = require('nodemailer');
const db = require('./database');
const multer = require('multer'); 
const serialize = require('serialize-javascript'); 
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const SQLiteStore = require('connect-sqlite3')(session);

const { body, validationResult } = require('express-validator');

const app = express();
const PORT = 3000;

// [추가] Nginx/Docker 환경에서 실제 IP 인식을 위해 필수
// (이 설정이 없으면 속도 제한이 127.0.0.1 또는 Docker Gateway IP 하나로 잡혀서 모든 유저가 차단될 수 있음)
app.set('trust proxy', 1);

// [추가] 응답 데이터 압축 (성능 최적화)
app.use(compression());

// [최종 해결] HTTP 보안 헤더 설정 (인라인 속성 및 외부 연결 허용)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            // 1. 스크립트 실행 허용 (인라인 스크립트 및 외부 CDN)
            scriptSrc: [
                "'self'", 
                "'unsafe-inline'", 
                "'unsafe-eval'", 
                "https://cdn.jsdelivr.net", 
                "https://cdnjs.cloudflare.com"
            ],
            // 2. [핵심 추가] 인라인 이벤트 핸들러(onclick 등) 허용
            scriptSrcAttr: ["'unsafe-inline'"],
            // 3. 스타일 시트 허용
            styleSrc: [
                "'self'", 
                "'unsafe-inline'", 
                "https://cdn.jsdelivr.net", 
                "https://cdnjs.cloudflare.com"
            ],
            // 4. 이미지 및 데이터 소스 허용
            imgSrc: ["'self'", "data:", "blob:"],
            // 5. 외부 통신 및 SourceMap 연결 허용 (콘솔 에러 해결)
            connectSrc: [
                "'self'", 
                "https://cdn.jsdelivr.net", 
                "https://cdnjs.cloudflare.com"
            ],
            // 6. 폰트 리소스 허용
            fontSrc: [
                "'self'", 
                "https://cdn.jsdelivr.net", 
                "https://cdnjs.cloudflare.com"
            ],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: [], // HTTPS 환경이므로 유지
        },
    },
    // [필수] 외부 리소스(CDN)를 사용하는 환경에서 반드시 false
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// 기본 설정 (Config)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public')); 
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// [수정] Multer 설정: 유형별/날짜별 동적 폴더 저장
const upload = multer({ 
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            let targetDir = uploadDir; // 기본값

            if (file.fieldname === 'signatureFile') {
                targetDir = path.join(uploadDir, 'signatures');
            } else if (file.fieldname === 'newAttachments') {
                const d = new Date();
                const year = d.getFullYear().toString();
                const month = String(d.getMonth() + 1).padStart(2, '0');
                targetDir = path.join(uploadDir, 'evidence', year, month);
            }

            // 폴더 자동 생성 (recursive)
            fs.mkdirSync(targetDir, { recursive: true });
            cb(null, targetDir);
        },
        filename: (req, file, cb) => {
            const tempName = `temp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            cb(null, tempName);
        }
    }),
    limits: { fileSize: 50 * 1024 * 1024 } 
});

// [보안 패치] 세션 설정 개선 (MemoryStore -> SQLiteStore)
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: './db', concurrentDB: true }),
  secret: process.env.SESSION_SECRET || 'secret-key-replace-me',
  resave: false, saveUninitialized: false, rolling: true, 
  cookie: { httpOnly: true, maxAge: 30 * 60 * 1000 }
}));

// [추가] 인증 관련 속도 제한 설정 (Brute Force 방어)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15분
    max: 10, // IP당 최대 10회 요청 가능 (15분 내)
    standardHeaders: true, // RateLimit-* 헤더 반환 (표준)
    legacyHeaders: false, // X-RateLimit-* 헤더 비활성화
    // 제한 초과 시 응답 메시지 (기존 클라이언트 처리 방식인 JSON 형태 유지)
    message: { status: 'Fail', msg: '로그인 시도 횟수가 초과되었습니다.<br>15분 후 다시 시도해주세요.' },
    // 제한 초과 시 로그 남기기 (선택 사항)
    handler: (req, res, next, options) => {
        console.warn(`[Security] Rate Limit Exceeded: ${req.ip}`);
        res.status(options.statusCode).json(options.message);
    }
});

// [CSRF 패치] CSRF 미들웨어 설정
const csrfProtection = csrf();
app.use(csrfProtection);
app.use((req, res, next) => { res.locals.csrfToken = req.csrfToken(); next(); });

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'outbound.daouoffice.com',
    port: parseInt(process.env.SMTP_PORT) || 465,
    secure: true, 
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    pool: true, maxConnections: 1, rateLimit: 3, timeout: 10000
});

// [추가] 유효성 검사 실행 및 에러 처리 헬퍼
const validate = (validations) => {
    return async (req, res, next) => {
        await Promise.all(validations.map(validation => validation.run(req)));
        const errors = validationResult(req);
        if (errors.isEmpty()) return next();
        return res.json({ status: 'Fail', msg: errors.array()[0].msg });
    };
};

// [추가] 회원가입 검증 규칙 (이게 정의되어 있어야 에러가 안 납니다)
const registerValidator = validate([
    body('email').isEmail().withMessage('유효한 이메일을 입력해주세요.').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('비밀번호는 6자 이상이어야 합니다.'),
    body('name').notEmpty().withMessage('이름을 입력해주세요.').trim().escape(),
    body('phone').matches(/^010-\d{3,4}-\d{4}$/).withMessage('전화번호 형식이 잘못되었습니다.'),
    body('position').notEmpty().withMessage('직책을 선택해주세요.').trim().escape(),
    body('generation').isInt({ min: 1 }).withMessage('대수를 선택해주세요.')
]);

// [추가] 로그인 검증 규칙
const loginValidator = validate([
    body('email').isEmail().withMessage('이메일 형식이 올바르지 않습니다.').normalizeEmail(),
    body('password').notEmpty().withMessage('비밀번호를 입력해주세요.')
]);

// [추가] 지출결의서 제출 검증 규칙
const expenditureValidator = validate([
    body('subject').notEmpty().withMessage('제목을 입력해주세요.').trim().escape(),
    body('bodyContent').notEmpty().withMessage('내용을 입력해주세요.').trim().escape(),
    body('totalAmount').isInt({ min: 0 }).withMessage('금액은 숫자여야 합니다.'),
    body('executionDate').notEmpty().withMessage('시행일자를 선택해주세요.')
]);

// 2. Helper Functions
function getTodayKST() {
    const d = new Date();
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function getUser(req) { return req.session.user || null; }

function checkAndMigrateDB() {
    console.log(">> [DB Check] 데이터베이스 컬럼 검사 시작...");
    
    const requiredColumns = [
        { name: 'locked_by_name', type: 'TEXT' },
        { name: 'locked_by_email', type: 'TEXT' },
        { name: 'locked_at', type: 'TEXT' }
    ];

    db.all("PRAGMA table_info(expenditures)", [], (err, columns) => {
        if (err) return console.error(">> [DB Error] 조회 실패:", err);
        
        const existingNames = columns.map(c => c.name);
        let added = 0;
        
        requiredColumns.forEach(col => {
            if (!existingNames.includes(col.name)) {
                console.log(`>> [DB Update] '${col.name}' 컬럼 추가 중...`);
                db.run(`ALTER TABLE expenditures ADD COLUMN ${col.name} ${col.type}`);
                added++;
            }
        });
        console.log(`>> [DB Check] 검사 완료. (추가된 컬럼: ${added}개)`);
    });
}

setTimeout(checkAndMigrateDB, 1000);

// [수정] saveFile: 서명 파일 저장 시 'signatures' 폴더 사용
async function saveFile(base64Data, type, prefix) {
  if (!base64Data) return "";
  try {
    let ext = '.jpg'; 
    if (type.includes('image/png')) ext = '.png';
    
    // 서명 전용 폴더 확보
    const sigDir = path.join(uploadDir, 'signatures');
    await fs.promises.mkdir(sigDir, { recursive: true });

    const filename = `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}${ext}`;
    const filePath = path.join(sigDir, filename);
    
    await fs.promises.writeFile(filePath, Buffer.from(base64Data, 'base64'), { mode: 0o644 });
    
    // DB에는 'signatures/파일명' 형태의 상대 경로 저장
    return path.join('signatures', filename).replace(/\\/g, '/');
  } catch (e) { console.error("File Save Error:", e); return ""; }
}

function getUserByPos(position) {
  return new Promise((resolve) => {
    db.get("SELECT email, name, phone, signature_path FROM users WHERE position = ? AND status = 'Approved' ORDER BY created_at DESC LIMIT 1", [position], (err, row) => {
        if(err || !row) resolve(null); else resolve(row);
    });
  });
}

// [수정] 문서 번호 채번 함수 (동시성 제어 적용)
// Transaction을 사용하여 중복 번호 발급을 원천 차단
function getNextDocNum(year) {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      db.run("BEGIN IMMEDIATE", (err) => { if (err) return reject(err); });
      db.run("INSERT OR IGNORE INTO doc_sequences (year, last_seq) VALUES (?, 0)", [year]);
      db.run("UPDATE doc_sequences SET last_seq = last_seq + 1 WHERE year = ?", [year], function(err) {
        if (err) { db.run("ROLLBACK"); return reject(err); }
      });
      db.get("SELECT last_seq FROM doc_sequences WHERE year = ?", [year], (err, row) => {
        if (err || !row) { db.run("ROLLBACK"); return reject(err || new Error("채번 실패")); }
        db.run("COMMIT");
        resolve(`사무국-${year}-${String(row.last_seq).padStart(4, '0')}`);
      });
    });
  });
}

function getSiteUrl() {
  return new Promise(r => db.get("SELECT value FROM settings WHERE key = 'site_url'", [], (e, row) => {
      let url = (row && row.value) ? row.value.trim() : 'http://localhost:8080';
      if(url.endsWith('/')) url = url.slice(0, -1); r(url);
  }));
}

function makeEmailHtml(docNum, subject, applicant, statusMsg, baseUrl) {
    return `<div style="padding:20px;border:1px solid #ddd;"><h2>${statusMsg}</h2><p>문서번호: ${docNum}</p><p>제목: ${subject}</p><p>기안자: ${applicant}</p><hr><a href="${baseUrl}/login?docNum=${docNum}">문서 확인</a></div>`;
}

async function sendEmail(to, sub, html) {
    if (!to) return;
    try { await transporter.sendMail({ from: process.env.SMTP_USER, to, subject: sub, html }); } catch (e) { console.error(e); }
}

function clearStaleLocks() {
    const timeout = new Date(Date.now() - 30 * 60 * 1000).toISOString();
    db.run("UPDATE expenditures SET locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE locked_at < ?", [timeout]);
}

function logAction(req, action, details) {
    const user = req.session.user;
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (ip.includes('::ffff:')) ip = ip.split(':').pop();
    db.run(`INSERT INTO audit_logs (user_email, user_name, action, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))`,
        [user ? user.email : 'Unknown', user ? user.name : 'System', action, details, ip], (err) => { if (err) console.error(err); });
}


// 3. 라우트 (Routes)
app.get(['/', '/login', '/register'], (req, res) => {
    if (getUser(req)) return res.redirect('/list');
    res.render('register', { targetDocNum: req.query.docNum || '' });
});

// [수정] 로그인 API에 authLimiter 미들웨어 적용
app.post('/api/login', authLimiter, (req, res) => {
  const { email, password } = req.body;
  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, row) => {
    if (err || !row) return res.json({ status: 'Fail', msg: '정보 불일치' });
    if (row.locked_until && new Date(row.locked_until) > new Date()) return res.json({ status: 'Fail', msg: '계정 잠김' });

    if (await bcrypt.compare(password, row.password)) {
        db.run("UPDATE users SET login_fail_count = 0, locked_until = NULL WHERE id = ?", [row.id]);
        if (row.status !== 'Approved') return res.json({ status: 'Fail', msg: '승인 대기 중' });
        req.session.user = row;
        req.session.save();
        logAction(req, 'LOGIN', '로그인 성공');
        res.json({ status: 'Approved', url: '/list' });
    } else {
        logAction(req, 'LOGIN_FAIL', `실패: ${email}`);
        let cnt = (row.login_fail_count || 0) + 1;
        if (cnt >= 5) {
            db.run("UPDATE users SET login_fail_count = ?, locked_until = ? WHERE id = ?", [cnt, new Date(Date.now() + 30*60000).toISOString(), row.id]);
            res.json({ status: 'Fail', msg: '5회 실패. 15분 잠김.' });
        } else {
            db.run("UPDATE users SET login_fail_count = ? WHERE id = ?", [cnt, row.id]);
            res.json({ status: 'Fail', msg: `정보 불일치 (${cnt}/5)` });
        }
    }
  });
});

// [수정] 회원가입 API: 중복 이메일 체크 및 사용자 친화적 메시지 적용
app.post('/api/register', authLimiter, registerValidator, async (req, res) => {
    const { email, password, name, position, phone, generation, signatureFile } = req.body;
    
    try {
        // 1. 이메일 중복 체크 (사용자 친화적 메시지 처리)
        const existingUser = await new Promise((resolve, reject) => {
            db.get("SELECT email FROM users WHERE email = ?", [email], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (existingUser) {
            return res.json({ 
                status: 'Error', 
                msg: '이미 사용 중인 이메일 주소입니다.<br>다른 이메일을 입력해 주세요.' 
            });
        }

        // 2. 비밀번호 해싱 및 가입 진행
        const hash = await bcrypt.hash(password, 10);
        let sigPath = "";
        if (signatureFile && signatureFile.data) {
            sigPath = await saveFile(signatureFile.data, signatureFile.type, 'SIG');
        }

        db.get("SELECT count(*) as count FROM users", [], (err, row) => {
            if (err) throw err;

            // 첫 가입자는 관리자(Admin), 이후는 일반 사용자(User)
            let role = (row && row.count === 0) ? 'Admin' : 'User';
            let status = (role === 'Admin') ? 'Approved' : 'Pending';

            const insertQuery = `
                INSERT INTO users (
                    email, password, name, position, phone, 
                    signature_path, generation, role, status, login_fail_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            `;

            db.run(insertQuery, 
                [email, hash, name, position, phone, sigPath, generation, role, status],
                (err) => {
                    if (err) {
                        console.error("Register DB Error:", err);
                        return res.json({ status: 'Error', msg: '가입 처리 중 오류가 발생했습니다.<br>잠시 후 다시 시도해 주세요.' });
                    }
                    res.json({ status: 'Success', msg: '회원가입 신청이 완료되었습니다.<br>관리자 승인 후 로그인 가능합니다.' });
                }
            );
        });
    } catch (e) {
        console.error("Register Error:", e);
        res.json({ status: 'Error', msg: '시스템 오류가 발생했습니다.' });
    }
});

app.get('/api/logout', (req, res) => {
  logAction(req, 'LOGOUT', '로그아웃');
  req.session.destroy(() => { res.clearCookie('token'); res.clearCookie('connect.sid'); res.redirect('/login'); });
});

app.use((req, res, next) => { if (req.session.user) { res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate'); return next(); } res.redirect('/login'); });

app.get('/list', (req, res) => {
    const user = getUser(req);
    let { page = 1, keyword = '', author = '' } = req.query;
    
    const limit = 10;
    let currentPage = parseInt(page);
    if (isNaN(currentPage) || currentPage < 1) currentPage = 1;
    const offset = (currentPage - 1) * limit;

    const sanitizedKeyword = keyword.replace(/%/g, '').trim();

    const authorListQuery = `SELECT DISTINCT appName FROM expenditures WHERE appName IS NOT NULL AND appName != '' ORDER BY appName ASC`;
    
    db.all(authorListQuery, [], (err, authors) => {
        let whereClause = "WHERE 1=1";
        let params = [];

        if (sanitizedKeyword) {
            whereClause += " AND (subject LIKE ? OR bodyContent LIKE ?)";
            const kw = `%${sanitizedKeyword}%`;
            params.push(kw, kw);
        }

        if (author) {
            whereClause += " AND appName = ?";
            params.push(author);
        }

        let authClause = "";
        if (user.role !== 'Admin') {
            authClause = ` AND (applicantEmail = ? 
                            OR status IN ('최종결재', '지급완료') 
                            OR (status = '제출완료' AND ? = '사무총장')
                            OR (status = '결재중' AND ? = '총동문회장'))`;
        }

        const countQuery = `SELECT COUNT(*) as total FROM expenditures ${whereClause} ${authClause}`;
        const countParams = user.role !== 'Admin' ? [...params, user.email, user.position, user.position] : params;

        db.get(countQuery, countParams, (err, countRow) => {
            const totalDocs = countRow ? countRow.total : 0;
            const totalPages = Math.ceil(totalDocs / limit);

            // [수정] 정렬 로직 변경 (Status 우선순위 적용)
            const finalQuery = `
                SELECT *, 
                (
                    (applicantEmail = ? AND (status = '작성중' OR status = '반려')) OR
                    (? = '사무총장' AND status = '제출완료') OR
                    (? = '총동문회장' AND status = '결재중') OR
                    (? = '재무국장' AND status = '최종결재')
                ) as spotlight
                FROM expenditures 
                ${whereClause} ${authClause}
                ORDER BY 
                    spotlight DESC,          -- 1순위: 내가 처리해야 할 문서 (결재/수정 등)
                    CASE status              -- 2순위: 요청하신 진행 상태 순서
                        WHEN '결재중' THEN 1
                        WHEN '제출완료' THEN 2
                        WHEN '작성중' THEN 3
                        WHEN '반려' THEN 3   -- (작성자가 수정해야 하므로 작성중과 묶음)
                        WHEN '최종결재' THEN 4
                        WHEN '지급완료' THEN 5
                        ELSE 6
                    END ASC,
                    docNum DESC              -- 3순위: 최신 문서 번호 순
                LIMIT ? OFFSET ?`;

            const queryParams = [
                user.email, user.position, user.position, user.position, 
                ...params, 
                ...(user.role !== 'Admin' ? [user.email, user.position, user.position] : []), 
                limit, offset 
            ];

            db.all(finalQuery, queryParams, (err, rows) => {
                if (err) console.error("Query Error:", err);
                
                res.render('ExpenditureList', { 
                    user, 
                    docs: rows || [], 
                    currentPage: currentPage, 
                    totalPages: totalPages,
                    authors: authors || [], 
                    query: { keyword: sanitizedKeyword, author }
                });
            });
        });
    });
});

app.get('/form', async (req, res) => {
    const user = getUser(req);
    const docNum = req.query.docNum;

    // [추가] 목록 페이지 상태 유지를 위한 파라미터 수신 (기본값 설정)
    const listPage = req.query.page || 1;
    const listKeyword = req.query.keyword || '';
    const listAuthor = req.query.author || '';
    
    // 목록으로 돌아가는 쿼리 스트링 미리 생성
    const listQueryStr = `page=${listPage}&keyword=${encodeURIComponent(listKeyword)}&author=${encodeURIComponent(listAuthor)}`;

    // [수정] 에러 발생 시 돌아갈 경로에도 쿼리 스트링 포함
    const renderAlertHTML = (msg) => `
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>알림</title>
            <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
            <style>body { background-color: #f0f2f5; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }</style>
        </head>
        <body>
            <script>
                document.addEventListener("DOMContentLoaded", function() {
                    Swal.fire({
                        icon: 'warning',
                        title: '접근 제한',
                        text: '${msg}',
                        confirmButtonText: '목록으로 돌아가기',
                        confirmButtonColor: '#3085d6',
                        allowOutsideClick: false,
                        allowEscapeKey: false
                    }).then(() => {
                        location.replace('/list?${listQueryStr}'); // [수정됨]
                    });
                });
            </script>
        </body>
        </html>
    `;

    let address = "주소 설정 필요";
    let presInfo = { name: "미지정", phone: "" };
    let secInfo = { name: "미지정", phone: "" };

    try {
        const addrRow = await new Promise(r => db.get("SELECT value FROM settings WHERE key = 'address'", [], (e, row) => r(row)));
        if (addrRow) address = addrRow.value;
        const pres = await getUserByPos('총동문회장');
        if (pres) presInfo = pres;
        const sec = await getUserByPos('사무총장');
        if (sec) secInfo = sec;
    } catch (e) { console.error("Info Load Error", e); }

    const commonData = {
        address: address,
        president: `${presInfo.name} (${presInfo.phone})`,
        secretary: `${secInfo.name} (${secInfo.phone})`,
        today: getTodayKST() 
    };

    const safeEmptyData = serialize({}, { isJSON: true });

    // [수정] render 호출 시 listPage, listKeyword, listAuthor 변수 전달
    if (!docNum) {
        return res.render('ExpenditureForm', { 
            user: user, 
            mode: 'WRITE', 
            docNum: '', 
            initDataJSON: safeEmptyData, 
            ...commonData,
            listPage,     // [추가]
            listKeyword,  // [추가]
            listAuthor    // [추가]
        });
    }

    db.get("SELECT * FROM expenditures WHERE docNum = ?", [docNum], (err, doc) => {
        if (err || !doc) return res.send(renderAlertHTML('존재하지 않거나 삭제된 문서입니다.'));

        if (doc.status === '작성중' && doc.applicantEmail !== user.email) {
            return res.send(renderAlertHTML('기안자에 의해 회수된 문서입니다. 목록을 갱신합니다.'));
        }

        if (doc.locked_at && doc.locked_by_email && doc.locked_by_email !== user.email) {
            const lockTime = new Date(doc.locked_at).getTime();
            const diffMin = (Date.now() - lockTime) / 1000 / 60; 
            
            if (diffMin < 3) { 
                const isDrafter = (doc.locked_by_email === doc.applicantEmail);
                const actionMsg = isDrafter ? "문서를 수정 중입니다." : "결재 진행 중입니다.";
                return res.send(renderAlertHTML(`현재 [${doc.locked_by_name}]님이 ${actionMsg}`));
            }
        }

        try { doc.items = JSON.parse(doc.items || "[]"); } catch(e) { doc.items = []; }
        doc.attachmentIds = doc.file_paths;
        doc.signatures = { applicant: doc.appSig, secretary: doc.secSig, president: doc.presSig };
        doc.applicantName = doc.applicantName || doc.appName;
        doc.applicantPos = doc.applicantPos || doc.appPos;
        doc.applicantPhone = doc.applicantPhone || doc.appPhone;

        let mode = 'VIEW';
        if (doc.applicantEmail === user.email && ['작성중', '반려'].includes(doc.status)) mode = 'WRITE';

        const safeInitData = serialize(doc, { isJSON: true });

        res.render('ExpenditureForm', { 
            user, 
            mode, 
            docNum, 
            initDataJSON: safeInitData, 
            ...commonData,
            listPage,     // [추가]
            listKeyword,  // [추가]
            listAuthor    // [추가]
        });
    });
});

// [수정 제안 코드] Multer 에러를 직접 잡기 위해 미들웨어 래핑
const uploadMiddleware = upload.array('newAttachments');

// [수정] 지출결의 제출 API: 사무총장/총동문회장 자동 결재 로직 보완
app.post('/api/submit', (req, res, next) => {
    uploadMiddleware(req, res, (err) => {
        if (err) return res.json({ status: 'Error', msg: err.code === 'LIMIT_FILE_SIZE' ? '파일 크기 초과 (50MB)' : err.message });
        next();
    });
}, expenditureValidator, async (req, res) => {
    const user = getUser(req);
    const f = req.body; 
    let finalDocNum = f.docNum || `TEMP-${Date.now()}`;
    let initialStatus = f.status; 
    let finalReqDate = f.reqDate || (initialStatus !== '작성중' ? getTodayKST() : "");
    
    // ============================================================
    // [핵심 수정] 직책별 자동 결재 및 상태 전환 로직
    // ============================================================
    if (initialStatus === '제출완료') {
        if (user.position === '사무총장') {
            // 사무총장이 제출하면 본인 승인을 건너뛰고 '결재중'(총동문회장 단계)으로 즉시 전환
            initialStatus = '결재중';
        } else if (user.position === '총동문회장') {
            // 총동문회장이 제출하면 즉시 '최종결재' 상태로 전환
            initialStatus = '최종결재';
            try { 
                // 최종결재 단계로 바로 가므로 정식 문서번호 채번
                finalDocNum = await getNextDocNum(new Date().getFullYear()); 
            } catch(e) {
                console.error("DocNum Generation Error:", e);
            }
        }
    }

    const uploadedFiles = req.files || [];
    const renamedFilePaths = [];

    try {
        let filePaths = [];
        if (f.existingFileIds) filePaths = f.existingFileIds.split(',').filter(x=>x);
        
        const { fileTypeFromFile } = await import('file-type');

        if (uploadedFiles.length > 0) {
            const timestamp = Date.now();
            const ALLOWED_EXTS = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf'];
            for (let i = 0; i < uploadedFiles.length; i++) {
                const file = uploadedFiles[i];
                const detectedType = await fileTypeFromFile(file.path);
                if (!detectedType || !ALLOWED_EXTS.includes(detectedType.ext)) {
                    await fs.promises.unlink(file.path).catch(()=>{});
                    throw new Error(`허용되지 않은 파일 형식: ${file.originalname}`);
                }
                const dirName = path.dirname(file.path);
                const safeExt = `.${detectedType.ext}`; 
                const finalFilename = `${finalDocNum}_증빙${filePaths.length + 1}_${timestamp}_${i}${safeExt}`;
                const finalPath = path.join(dirName, finalFilename);
                await fs.promises.rename(file.path, finalPath);
                renamedFilePaths.push(finalPath);
                const relativePath = path.relative(uploadDir, finalPath).replace(/\\/g, '/');
                filePaths.push(relativePath);
            }
        }
       
        const filePathsStr = filePaths.join(",");
       
        let itemsStr = f.items; 
        try { if (typeof f.items !== 'string') itemsStr = JSON.stringify(f.items); } catch(e) { itemsStr = "[]"; }

        // [중요] params의 9번째 인자인 initialStatus가 위에서 변경된 값을 사용하도록 확인
        const params = [
            finalDocNum, user.email, f.subject, f.bodyContent, f.totalAmount, f.executionDate, finalReqDate, 
            itemsStr, initialStatus, // <-- 여기서 '결재중' 또는 '최종결재'로 들어감
            user.position, user.name, user.phone, user.signature_path, 
            filePathsStr
        ];
       
        const afterSave = async () => {
            db.run("UPDATE expenditures SET locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE docNum=?", [finalDocNum]);

            let msg = "제출되었습니다.";
            if (initialStatus === '작성중') msg = "임시저장 되었습니다.";
            else if (initialStatus === '결재중') msg = "제출 및 사무총장 자동 승인 완료 (총동문회장 결재 단계).";
            else if (initialStatus === '최종결재') msg = "제출 및 최종 승인 완료 (재무국장 지급 단계).";

            res.json({msg: msg});

            // 메일 발송 로직
            try {
                const baseUrl = await getSiteUrl();
                const appInfoStr = `${user.position} ${user.name}`;
                let targetPos = "";
                // 바뀐 initialStatus에 따라 수신자 결정
                if (initialStatus === '제출완료') targetPos = '사무총장';
                else if (initialStatus === '결재중') targetPos = '총동문회장';
                else if (initialStatus === '최종결재') targetPos = '재무국장';

                if (targetPos) {
                    const recipient = await getUserByPos(targetPos);
                    if (recipient && recipient.email) {
                        const mailSubject = (initialStatus === '최종결재') ? `[지급요청] ${f.subject}` : `[결재요청] ${f.subject}`;
                        await sendEmail(recipient.email, mailSubject, makeEmailHtml(finalDocNum, f.subject, appInfoStr, "결재(지급) 요청", baseUrl));
                    }
                }
            } catch (e) { console.error("[Mail Error]", e); }
        };

        // DB 저장 로직 (생략 - 기존과 동일하게 params를 사용하여 INSERT/UPDATE 수행)
        db.get("SELECT docNum FROM expenditures WHERE docNum = ?", [finalDocNum], (err, row) => {
            if (row) {
                let updateQuery = `UPDATE expenditures SET subject=?, bodyContent=?, totalAmount=?, executionDate=?, reqDate=?, items=?, status=?, file_paths=? WHERE docNum=?`;
                db.run(updateQuery, [f.subject, f.bodyContent, f.totalAmount, f.executionDate, finalReqDate, itemsStr, initialStatus, filePathsStr, finalDocNum], 
                    (err) => err ? res.json({msg: err.message}) : afterSave());
            } else {
                const insertQuery = `INSERT INTO expenditures (
                    docNum, applicantEmail, subject, bodyContent, totalAmount, executionDate, reqDate,
                    items, status, appPos, appName, appPhone, appSig, file_paths, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`;
                db.run(insertQuery, params, (err) => {
                    if (err) return res.json({msg: "DB 오류: " + err.message});
                    afterSave();
                });
            }
        });
        
    } catch(e) {
        for (const p of renamedFilePaths) await fs.promises.unlink(p).catch(()=>{});
        for (const f of uploadedFiles) await fs.promises.unlink(f.path).catch(()=>{});
        res.json({status: 'Error', msg: e.toString()}); 
    }
});

// [수정] 승인 API (비동기 파일 처리 적용)
app.post('/api/approve', (req, res) => {
    const user = getUser(req);
    const { docNum, action } = req.body;
    const todayStr = getTodayKST();

    db.get("SELECT * FROM expenditures WHERE docNum = ?", [docNum], async (err, doc) => {
        if(!doc) return res.json({ msg: "문서를 찾을 수 없습니다." });

        if (action === 'REJECT') {
            logAction(req, 'DOC_REJECT', `문서 반려 처리: ${docNum}`);

            db.run("UPDATE expenditures SET status='반려', locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE docNum=?", [docNum], async (err) => {
                res.json({ msg: "반려되었습니다." });
                if(doc.applicantEmail) {
                    try {
                        const baseUrl = await getSiteUrl();
                        const appInfo = `${doc.appPos || doc.applicantPos} ${doc.appName || doc.applicantName}`;
                        await sendEmail(doc.applicantEmail, `[반려] ${doc.subject}`, makeEmailHtml(docNum, doc.subject, appInfo, "반려 알림", baseUrl));
                    } catch(e){}
                }
            });
        } else {
            let nextStatus = doc.status;
            let updateQuery = "";
            let params = [];
            let newDocNum = docNum;
            let nextRole = "";

            if (user.position === '사무총장') {
                nextStatus = '결재중'; nextRole = '총동문회장';
                updateQuery = "UPDATE expenditures SET status=?, secName=?, secSig=?, secDate=? WHERE docNum=?";
                params = [nextStatus, user.name, user.signature_path, todayStr, docNum];
            } else if (user.position === '총동문회장') {
                nextStatus = '최종결재'; nextRole = '재무국장';
                
                try { 
                    newDocNum = await getNextDocNum(new Date().getFullYear()); 
                } catch(e) {
                    return res.json({ status: 'Error', msg: '문서 번호 생성 실패: ' + e.message });
                }

                let newFilePaths = doc.file_paths;
                const renameHistory = []; 

                if (doc.file_paths) {
                    const oldFiles = doc.file_paths.split(',');
                    const renamedFiles = [];
                    const timestamp = Date.now();
                    
                    try {
                        for (let index = 0; index < oldFiles.length; index++) {
                            let oldName = oldFiles[index].trim(); // 예: evidence/2026/02/TEMP_...
                            if (!oldName) continue;
                            
                            const oldPath = path.join(uploadDir, oldName);
                            
                            // [수정 1] 파일이 있던 디렉토리 경로 추출 (예: evidence/2026/02)
							const fileDir = path.dirname(oldName);
							
							const ext = path.extname(oldName);
							const newFileNameOnly = `${newDocNum}_증빙${index + 1}_${timestamp}${ext}`;
                            
							// [수정 2] 새 경로 = uploadDir + 원래 디렉토리 + 새 파일명
							const newPath = path.join(uploadDir, fileDir, newFileNameOnly);
                            
							// [수정 3] DB 저장용 상대 경로 (Windows 역슬래시 처리 포함)
							const newDbPath = path.join(fileDir, newFileNameOnly).replace(/\\/g, '/');

                            try {
                                await fs.promises.access(oldPath);
                                await fs.promises.rename(oldPath, newPath);
                                
                                renameHistory.push({ oldPath, newPath });
								renamedFiles.push(newDbPath); // [수정 4] DB에는 상대 경로 저장
                            } catch (err) {
                                console.warn(`File rename warning: ${oldName} not found.`);
                                renamedFiles.push(oldName);
                            }
                        }
                        newFilePaths = renamedFiles.join(',');

                    } catch (fileErr) {
                        console.error("File Rename Error, Rolling back...", fileErr);
                        for (const history of renameHistory) {
                            await fs.promises.rename(history.newPath, history.oldPath).catch(()=>{});
                        }
                        return res.json({ msg: "처리 중 오류가 발생하여 취소되었습니다." });
                    }
                }

                // 3. DB 업데이트 준비
                updateQuery = "UPDATE expenditures SET docNum=?, status=?, presName=?, presSig=?, presDate=?, presidentSignedDate=?, file_paths=? WHERE docNum=?";
                params = [newDocNum, nextStatus, user.name, user.signature_path, todayStr, todayStr, newFilePaths, docNum];

                // 4. DB 업데이트 실행 (실패 시 파일 롤백 수행)
                db.run(updateQuery, params, async function(err) {
                    if (err) {
                        console.error("DB Update Error during approval:", err);
                        
                        // [핵심] DB 업데이트가 실패했으므로, 바꿨던 파일 이름들을 다시 원상복구(Rollback) 합니다.
                        for (const history of renameHistory) {
                            try {
                                await fs.promises.rename(history.newPath, history.oldPath);
                                console.log(`Rollback file: ${history.newPath} -> ${history.oldPath}`);
                            } catch (rbErr) {
                                console.error(`Rollback failed for ${history.newPath}`, rbErr);
                            }
                        }
                        return res.json({ msg: "DB 저장 오류로 승인이 취소되었습니다.<br>관리자에게 문의하시기 바랍니다." });
                    }

                    // 성공 시 로그 및 메일 발송 (기존 로직)
                    logAction(req, 'DOC_APPROVE', `문서 승인(${nextStatus}): ${newDocNum}`);
                    db.run("UPDATE expenditures SET locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE docNum=?", [newDocNum]);
                    
                    res.json({msg: "승인 완료"});
                    
                    // (메일 발송 로직 생략 - 기존과 동일)
                    try {
                        const baseUrl = await getSiteUrl();
                        const appInfo = `${doc.appPos || doc.applicantPos} ${doc.appName || doc.applicantName}`;
                        const nextPerson = await getUserByPos(nextRole);
                        if (nextPerson && nextPerson.email) await sendEmail(nextPerson.email, `[결재요청] ${doc.subject}`, makeEmailHtml(newDocNum, doc.subject, appInfo, "결재 요청", baseUrl));
                    } catch(e){}
                });

                // 총동문회장 로직 끝, 리턴하여 아래 중복 실행 방지
                return; 

            } else if (user.position === '재무국장') {
                nextStatus = '지급완료';
                updateQuery = "UPDATE expenditures SET status=?, payDate=? WHERE docNum=?";
                params = [nextStatus, todayStr, docNum];
            }

            if(updateQuery) {
                db.run(updateQuery, params, async (err) => {
                    if(err) return res.json({msg:err.message});
                    
                    logAction(req, 'DOC_APPROVE', `문서 승인(${nextStatus}): ${newDocNum}`);

                    db.run("UPDATE expenditures SET locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE docNum=?", [newDocNum]);
                    res.json({msg: "승인 완료"});
                    
                    try {
                        const baseUrl = await getSiteUrl();
                        const appInfo = `${doc.appPos || doc.applicantPos} ${doc.appName || doc.applicantName}`;
                        if (nextStatus === '지급완료') {
                             if(doc.applicantEmail) await sendEmail(doc.applicantEmail, `[지급완료] ${doc.subject}`, makeEmailHtml(newDocNum, doc.subject, appInfo, "지급 완료", baseUrl));
                        } else {
                             const nextPerson = await getUserByPos(nextRole);
                             if (nextPerson && nextPerson.email) await sendEmail(nextPerson.email, `[결재요청] ${doc.subject}`, makeEmailHtml(newDocNum, doc.subject, appInfo, "결재 요청", baseUrl));
                        }
                    } catch(e){}
                });
            } else {
                res.json({msg: "승인 권한이 없습니다."});
            }
        }
    });
});

app.get('/profile', (req, res) => {
    const user = getUser(req);
    db.get("SELECT * FROM users WHERE email = ?", [user.email], (err, row) => {
        if (err || !row) return res.redirect('/login');
        delete row.password;
        
        const safeUserData = serialize(row, { isJSON: true });
        res.render('profile', { user: row, userDataJSON: safeUserData });
    });
});

app.post('/api/profile/update', async (req, res) => {
    const user = getUser(req);
    const { name, generation, position, phone, password, signatureFile } = req.body;

    let query = "UPDATE users SET name=?, generation=?, position=?, phone=?";
    let params = [name, generation, position, phone];

    if (password) {
        const hash = await bcrypt.hash(password, 10);
        query += ", password=?";
        params.push(hash);
    }
    if (signatureFile && signatureFile.data) {
        // [성능 패치 1.1] saveFile 비동기 호출 (await 추가)
        const fname = await saveFile(signatureFile.data, signatureFile.type, 'SIG');
        query += ", signature_path=?";
        params.push(fname);
    }
    query += " WHERE email=?";
    params.push(user.email);

    db.run(query, params, (err) => {
        if (err) return res.json({ status: 'Error', msg: err.message });
        
        db.get("SELECT * FROM users WHERE email = ?", [user.email], (err, updatedUser) => {
            req.session.user = updatedUser;
            req.session.save();
            res.json({ status: 'Success', msg: '수정되었습니다.' });
			logAction(req, 'UPDATE_PROFILE', `본인 정보 수정: ${name}`);
        });
    });
});

app.post('/api/lock/acquire', (req, res) => {
    const timeout = new Date(Date.now() - 3 * 60 * 1000).toISOString();
    db.run("UPDATE expenditures SET locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE locked_at < ?", [timeout]);

    const user = getUser(req);
    const { docNum } = req.body;
    const now = new Date().toISOString();

    db.get("SELECT status, applicantEmail, locked_by_name, locked_by_email, locked_at FROM expenditures WHERE docNum = ?", [docNum], (err, row) => {
        if(err || !row) return res.json({ status: 'Error', msg: '문서가 없습니다.' });
		
		// [개선] 결재가 완료된 상태는 수정 가능성이 없으므로 Lock을 시도하지 않음
        if (['최종결재', '지급완료'].includes(row.status)) {
            return res.json({ status: 'Success', message: 'Read-only mode (No lock required)' });
        }

        if (row.status === '작성중' && user.email !== row.applicantEmail) {
            return res.json({ status: 'Recalled', msg: '기안자에 의해 회수된 문서입니다.' });
        }

        if (row.locked_at && row.locked_by_email && row.locked_by_email !== user.email) {
            const lastLock = new Date(row.locked_at).getTime();
            const diffMin = (Date.now() - lastLock) / 1000 / 60;
            
            if (diffMin < 3) {
                const isDrafter = (row.locked_by_email === row.applicantEmail);
                const actionMsg = isDrafter ? "문서를 수정 중입니다." : "결재 진행 중입니다.";
                return res.json({ status: 'Locked', msg: `현재 [${row.locked_by_name}]님이 ${actionMsg}` });
            }
        }

        db.run("UPDATE expenditures SET locked_by_name=?, locked_by_email=?, locked_at=? WHERE docNum=?",
            [user.name, user.email, now, docNum],
            (err) => {
                if(err) return res.json({ status: 'Error', msg: err.message });
                res.json({ status: 'Success' });
            }
        );
    });
});

app.post('/api/lock/release', (req, res) => {
    const user = getUser(req);
    const { docNum } = req.body;

    console.log(`\n--- [Lock Release Request] ---`);
    console.log(`User: ${user ? user.name : 'Unknown'}`);
    console.log(`DocNum: ${docNum}`);
    console.log(`Body Raw:`, req.body); 

    if (!user) {
        console.log(`>> [FAIL] 사용자 세션 없음`);
        return res.json({ status: 'Error', msg: '로그인 필요' });
    }

    db.run("UPDATE expenditures SET locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE docNum=? AND locked_by_email=?",
        [docNum, user.email],
        function(err) {
            if (err) {
                console.error(`>> [ERROR] DB Error: ${err.message}`);
                return res.json({ status: 'Error' });
            }
            if (this.changes > 0) {
                console.log(`>> [SUCCESS] Lock 해제 완료`);
            } else {
                console.log(`>> [INFO] 해제할 Lock이 없거나(이미 해제됨) 본인 Lock이 아님`);
            }
            res.json({ status: 'Success' });
        }
    );
});

app.post('/api/recall', (req, res) => {
    const user = getUser(req);
    const { docNum } = req.body;
    
    const query = `UPDATE expenditures SET status='작성중', 
                   secName=NULL, secSig=NULL, secDate=NULL,
                   presName=NULL, presSig=NULL, presDate=NULL, presidentSignedDate=NULL,
                   locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL
                   WHERE docNum=? AND applicantEmail=? AND status IN ('제출완료', '결재중')`;

    db.run(query, [docNum, user.email], function(err) {
        if (err) return res.json({ status: 'Error', msg: err.message });
        if (this.changes === 0) return res.json({ status: 'Error', msg: '회수할 수 없는 상태입니다.' });
        res.json({ status: 'Success', msg: '문서가 회수되었습니다.' });
    });
});

// [수정] 다운로드 API: 서명 파일 허용 로직 추가
app.get('/api/download/*', (req, res) => {
    const user = getUser(req);
    if (!user) return res.status(401).send('로그인 필요');

    // req.params[0]에 'evidence/2026/02/파일명.jpg' 등이 담김
    const relativePath = req.params[0]; 
    
    // [보안 패치] Path Traversal 방어 강화
    // 1. 절대 경로로 변환 (.. 등이 섞여 있어도 실제 경로로 해석됨)
    const safePath = path.resolve(uploadDir, relativePath);

    // 2. 변환된 경로가 반드시 uploadDir(업로드 루트) 내부인지 확인
    // (예: /usr/src/app/uploads/evidence/... 는 허용, /usr/src/app/server.js 는 차단)
    if (!safePath.startsWith(uploadDir)) {
        console.warn(`[Security] Path Traversal Attempt Blocked: ${req.ip} - ${relativePath}`);
        return res.status(403).send('잘못된 경로 (Access Denied)');
    }

    const filePath = safePath;

    // ============================================================
    // [핵심 추가] 서명 파일(signatures 폴더)인 경우 예외 처리
    // ============================================================
    // (기존 코드 유지: 경로 체크가 완료된 filePath를 사용)
    if (relativePath.startsWith('signatures/') || relativePath.startsWith('signatures\\')) {
        return fs.access(filePath, fs.constants.F_OK, (err) => {
            if (err) return res.status(404).send('서명 파일을 찾을 수 없습니다.');
            res.download(filePath);
        });
    }

    // 증빙 자료(evidence)인 경우: DB 조회하여 권한 체크
    const query = "SELECT applicantEmail, status FROM expenditures WHERE file_paths LIKE ?";
    db.get(query, [`%${relativePath}%`], async (err, row) => {
        if (err) {
            console.error("Download DB Error:", err);
            return res.status(500).send("시스템 오류");
        }
        
        // 권한 체크 로직
        if (!row) {
            // 파일은 있는데 지출결의서 증빙 목록에 없는 경우 -> 관리자만 허용
            if (user.role !== 'Admin') {
                return res.status(403).send('권한이 없습니다 (문서 정보 없음).');
            }
        } else {
            // A. 공개 가능한 상태인가?
            const isPublicStatus = ['최종결재', '지급완료'].includes(row.status);
            // B. 내 문서인가? 관리자인가?
            const isOwnerOrAdmin = (row.applicantEmail === user.email) || (user.role === 'Admin');
            // C. 결재권자인가?
            const isApprover = ['사무총장', '총동문회장', '재무국장'].includes(user.position);

            if (!isPublicStatus && !isOwnerOrAdmin && !isApprover) {
                return res.status(403).send('권한이 없습니다 (결재 진행 중인 타인의 문서).');
            }
        }

        // 파일 전송
        try {
            await fs.promises.access(filePath);
            res.download(filePath);
        } catch (e) {
            res.status(404).send('파일 없음');
        }
    });
});

app.post('/api/file/delete', async (req, res) => {
    const user = req.session.user;
    if (!user) return res.json({ status: 'Error', msg: '로그인이 필요합니다.' });

    const fileId = req.body.fileId;
    const filePath = path.join(uploadDir, fileId);

    // [성능 패치 1.1] 파일 삭제 비동기 처리
    try {
        await fs.promises.unlink(filePath);
    } catch (e) {
        console.error("File Delete Error (Ignored):", e.message);
    }

    const likePattern = `%${fileId}%`;
    
    db.get("SELECT docNum, file_paths FROM expenditures WHERE file_paths LIKE ?", [likePattern], (err, row) => {
        if (err || !row) {
            return res.json({ status: 'Success', msg: '파일이 삭제되었습니다.' });
        }

        let paths = row.file_paths.split(',').map(s => s.trim());
        paths = paths.filter(p => p !== fileId && p !== "");
        const newPaths = paths.join(',');

        db.run("UPDATE expenditures SET file_paths = ? WHERE docNum = ?", [newPaths, row.docNum], (updateErr) => {
            if (updateErr) return res.json({ status: 'Error', msg: 'DB 업데이트 실패' });
            res.json({ status: 'Success', msg: '파일 및 DB 기록이 삭제되었습니다.' });
        });
    });
});

app.get('/admin', (req, res) => {
    if (req.session.user.role !== 'Admin') return res.redirect('/login');
    res.render('admin'); 
});

// ==========================================
// [추가] 관리자 기능 보완 (Settings & User Manage)
// ==========================================

app.get('/api/admin/settings', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'Admin') return res.json({});
    
    db.all("SELECT key, value FROM settings", [], (err, rows) => {
        if (err) return res.json({});
        const settings = {};
        rows.forEach(r => settings[r.key] = r.value);
        res.json(settings);
    });
});

app.post('/api/admin/settings', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'Admin') {
        return res.json({ status: 'Error', msg: '권한이 없습니다.' });
    }
    const { address, site_url } = req.body;

    db.serialize(() => {
        db.run("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ['address', address]);
        db.run("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ['site_url', site_url], (err) => {
            if (err) res.json({ status: 'Error', msg: err.message });
            else res.json({ status: 'Success', msg: '설정이 저장되었습니다.' });
        });
    });
});

app.post('/api/admin/user/unlock', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'Admin') return res.json({ status: 'Error' });
    
    const { id } = req.body;
    db.run("UPDATE users SET login_fail_count = 0, locked_until = NULL WHERE id = ?", [id], (err) => {
        if (err) return res.json({ status: 'Error', msg: err.message });
        res.json({ status: 'Success', msg: '잠금이 해제되었습니다.' });
    });
});

app.post('/api/admin/user/delete', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'Admin') return res.json({ status: 'Error' });
    
    const { id } = req.body;
    db.run("DELETE FROM users WHERE id = ?", [id], (err) => {
        if (err) return res.json({ status: 'Error', msg: err.message });
        res.json({ status: 'Success', msg: '사용자가 삭제되었습니다.' });
    });
});

app.post('/api/admin/user/update', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'Admin') {
        return res.json({ status: 'Error', msg: '권한이 없습니다.' });
    }

    const { id, name, position, phone, generation, status, role, newPassword, signatureFile } = req.body;

    db.get("SELECT * FROM users WHERE id = ?", [id], async (err, oldUser) => {
        if (err || !oldUser) return res.json({ status: 'Error', msg: '사용자를 찾을 수 없습니다.' });

        let query = "UPDATE users SET name=?, position=?, phone=?, generation=?, status=?, role=?";
        let params = [name, position, phone, generation, status, role];
        let changes = []; 

        if (oldUser.name != name) changes.push(`이름: ${oldUser.name} -> ${name}`);
        if (oldUser.position != position) changes.push(`직책: ${oldUser.position} -> ${position}`);
        if (oldUser.phone != phone) changes.push(`전화: ${oldUser.phone} -> ${phone}`);
        if (oldUser.generation != generation) changes.push(`대수: ${oldUser.generation} -> ${generation}`);
        if (oldUser.status != status) changes.push(`상태: ${oldUser.status} -> ${status}`);
        if (oldUser.role != role) changes.push(`권한: ${oldUser.role} -> ${role}`);

        if (newPassword) {
            const hash = await bcrypt.hash(newPassword, 10);
            query += ", password=?";
            params.push(hash);
            changes.push(`비밀번호: 변경됨`);
        }

        if (signatureFile) {
            // [성능 패치 1.1] saveFile 비동기 호출 (await 추가)
            const fname = await saveFile(signatureFile.data, signatureFile.type, 'SIG');
            query += ", signature_path=?";
            params.push(fname);
            changes.push(`서명: 변경됨`);
        }

        query += " WHERE id=?";
        params.push(id);

        db.run(query, params, (updateErr) => {
            if (updateErr) return res.json({ status: 'Error', msg: updateErr.message });

            const logDetail = changes.length > 0 
                ? `관리자 정보 수정 (ID: ${id}, 대상: ${oldUser.name}) - [ ${changes.join(', ')} ]`
                : `관리자 정보 수정 (ID: ${id}, 대상: ${oldUser.name}) - 변경 사항 없음`;

            logAction(req, 'ADMIN_USER_UPDATE', logDetail);
            res.json({ status: 'Success', msg: '수정되었습니다.' });
        });
    });
});

app.post('/api/admin/user/approve', (req, res) => {
    if (req.session.user.role !== 'Admin') return res.json({ status: 'Error' });
    db.run("UPDATE users SET status = 'Approved' WHERE id = ?", [req.body.id], (err) => {
        if (!err) logAction(req, 'ADMIN_USER_APPROVE', `사용자 가입 승인 (대상ID: ${req.body.id})`); 
        res.json({ status: 'Success', msg: '승인되었습니다.' });
    });
});

app.get('/api/admin/users', (req, res) => {
    if (req.session.user.role !== 'Admin') return res.status(403).json([]);
    db.all("SELECT * FROM users ORDER BY created_at DESC", [], (err, rows) => res.json(rows));
});

// [수정] 관리자용 지출결의서 목록 (검색 + 페이징)
app.get('/api/admin/list', (req, res) => {
    const user = req.session.user;
    if (!user || user.role !== 'Admin') return res.json({ docs: [], total: 0 });

    const page = parseInt(req.query.page) || 1;
    const limit = 10; // 페이지당 10개
    const offset = (page - 1) * limit;
    const keyword = req.query.keyword || '';

    let whereClause = "WHERE 1=1";
    let params = [];

    if (keyword) {
        whereClause += " AND (docNum LIKE ? OR subject LIKE ? OR appName LIKE ?)";
        const k = `%${keyword}%`;
        params.push(k, k, k);
    }

    // 1. 전체 개수 조회
    db.get(`SELECT COUNT(*) as count FROM expenditures ${whereClause}`, params, (err, countRow) => {
        if (err) return res.json({ docs: [], total: 0 });
        const total = countRow.count;

        // 2. 데이터 조회
        const query = `SELECT * FROM expenditures ${whereClause} ORDER BY docNum DESC LIMIT ? OFFSET ?`;
        db.all(query, [...params, limit, offset], (err, rows) => {
            if (err) return res.json({ docs: [], total: 0 });
            
            const docs = rows.map(doc => ({
                docNum: doc.docNum,
                subject: doc.subject,
                applicant: doc.appName || doc.applicantName || doc.name || '-',
                stage: doc.status 
            }));

            res.json({ docs, total, page, totalPages: Math.ceil(total / limit) });
        });
    });
});

app.post('/api/admin/delete_doc', async (req, res) => {
    const user = req.session.user;
    if (!user || user.role !== 'Admin') {
        return res.json({ status: 'Error', msg: '권한이 없습니다.' });
    }

    const { docNum } = req.body;

    db.get("SELECT file_paths FROM expenditures WHERE docNum = ?", [docNum], async (err, row) => {
        if (err) return res.json({ status: 'Error', msg: 'DB 조회 실패' });
        if (!row) return res.json({ status: 'Error', msg: '문서가 존재하지 않습니다.' });

        if (row.file_paths) {
            const files = row.file_paths.split(',');
            // [성능 패치 1.1] 파일 삭제 루프 비동기 처리
            for (const fileName of files) {
                const filePath = path.join(uploadDir, fileName.trim());
                try {
                     await fs.promises.unlink(filePath);
                     console.log(`[Admin] 파일 삭제됨: ${fileName}`);
                } catch (e) {
                     console.error(`[Admin] 파일 삭제 실패 (무시): ${fileName}`, e.message);
                }
            }
        }

        db.run("DELETE FROM expenditures WHERE docNum = ?", [docNum], (err) => {
            if (err) return res.json({ status: 'Error', msg: err.message });
            
            console.log(`[Admin] 지출결의서 삭제 완료: ${docNum}`);
            res.json({ status: 'Success', msg: '삭제되었습니다.' });
			logAction(req, 'DELETE_DOC', `문서 영구 삭제: ${docNum}`);
        });
    });
});

// [수정] 감사 로그 조회 (검색 + 페이징)
app.get('/api/admin/logs', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'Admin') return res.status(403).json({});

    const page = parseInt(req.query.page) || 1;
    const limit = 15; // 로그는 페이지당 15개
    const offset = (page - 1) * limit;
    const keyword = req.query.keyword || '';

    let whereClause = "WHERE 1=1";
    let params = [];

    if (keyword) {
        whereClause += " AND (user_name LIKE ? OR action LIKE ? OR details LIKE ? OR ip_address LIKE ?)";
        const k = `%${keyword}%`;
        params.push(k, k, k, k);
    }

    db.get(`SELECT COUNT(*) as count FROM audit_logs ${whereClause}`, params, (err, countRow) => {
        if (err) return res.json({ logs: [], total: 0 });
        const total = countRow.count;

        const query = `SELECT * FROM audit_logs ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`;
        db.all(query, [...params, limit, offset], (err, rows) => {
            res.json({ logs: rows, total, page, totalPages: Math.ceil(total / limit) });
        });
    });
});

app.use((req, res) => res.redirect('/login'));

app.use((err, req, res, next) => {
    if (err.code !== 'EBADCSRFTOKEN') return next(err);
    console.error(`[CSRF Error] ${req.ip} - ${req.originalUrl}`);
    res.status(403).json({ status: 'Error', msg: '보안 토큰이 만료되었거나 유효하지 않습니다.<br>페이지를 새로고침하세요.' });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));