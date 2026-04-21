const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

// ===== 로그인 실패 전용 카운터 (express-rate-limit 대체) =====
// Map: ip -> { count: 실패횟수, firstFailAt: 첫 실패 시각 }
const loginFailMap = new Map();

const LOGIN_FAIL_MAX    = 10;               // 최대 실패 허용 횟수
const LOGIN_FAIL_WINDOW = 15 * 60 * 1000;  // 15분 윈도우

// 미들웨어: 요청 전에 차단 여부만 확인 (카운터 증가 안 함)
function loginRateLimiter(req, res, next) {
    const ip = req.ip;
    const now = Date.now();
    const record = loginFailMap.get(ip);

    if (record) {
        // 윈도우 경과 시 자동 초기화
        if (now - record.firstFailAt > LOGIN_FAIL_WINDOW) {
            loginFailMap.delete(ip);
        } else if (record.count >= LOGIN_FAIL_MAX) {
            const remainMin = Math.ceil((LOGIN_FAIL_WINDOW - (now - record.firstFailAt)) / 60000);
            console.warn(`[Security] Login Rate Limit Exceeded: ${ip} (실패 ${record.count}회, 잔여 ${remainMin}분)`);
            return res.status(429).json({
                status: 'Fail',
                msg: `로그인 시도 횟수가 초과되었습니다.<br>${remainMin}분 후 다시 시도해주세요.`
            });
        }
    }
    next();
}

// 실패 시 호출 — 카운터 증가
function recordLoginFailure(ip) {
    const now  = Date.now();
    const record = loginFailMap.get(ip);
    if (!record) {
        loginFailMap.set(ip, { count: 1, firstFailAt: now });
    } else {
        record.count++;
    }
}

// 성공 시 호출 — 카운터 즉시 초기화
function resetLoginAttempts(ip) {
    loginFailMap.delete(ip);
}

// 회원가입 전용: 1시간에 5회 (단순 횟수 제한으로 충분)
const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { status: 'Fail', msg: '회원가입 시도 횟수가 초과되었습니다.<br>1시간 후 다시 시도해주세요.' },
    handler: (req, res, next, options) => {
        console.warn(`[Security] Register Rate Limit Exceeded: ${req.ip}`);
        res.status(options.statusCode).json(options.message);
    }
});

// ===== 이하 기존 코드 유지 =====
const validate = (validations) => async (req, res, next) => {
    await Promise.all(validations.map(v => v.run(req)));
    const errors = validationResult(req);
    if (errors.isEmpty()) return next();
    return res.json({ status: 'Fail', msg: errors.array()[0].msg });
};

function validatePassword(password) {
    if (!password || password.length < 8)
        return '비밀번호는 8자 이상이어야 합니다.';
    if (!/[a-zA-Z]/.test(password))
        return '비밀번호에 영문자를 포함해야 합니다.';
    if (!/[0-9]/.test(password))
        return '비밀번호에 숫자를 포함해야 합니다.';
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password))
        return '비밀번호에 특수문자를 포함해야 합니다.';
    return null;
}

const registerValidator = validate([
    body('email').isEmail().withMessage('유효한 이메일을 입력해주세요.').normalizeEmail(),
    body('password').custom(value => {
        const err = validatePassword(value);
        if (err) throw new Error(err);
        return true;
    }),
    body('name').notEmpty().withMessage('이름을 입력해주세요.').trim(),
    body('phone').matches(/^010-\d{3,4}-\d{4}$/).withMessage('전화번호 형식이 잘못되었습니다.'),
    body('position').notEmpty().withMessage('직책을 선택해주세요.').trim(),
    body('generation').isInt({ min: 1 }).withMessage('대수를 선택해주세요.')
]);

const loginValidator = validate([
    body('email').isEmail().withMessage('이메일 형식이 올바르지 않습니다.').normalizeEmail(),
    body('password').notEmpty().withMessage('비밀번호를 입력해주세요.')
]);

const expenditureValidator = validate([
    body('subject').notEmpty().withMessage('제목을 입력해주세요.').trim(),
    body('bodyContent').notEmpty().withMessage('내용을 입력해주세요.').trim(),
    body('totalAmount').isInt({ min: 0 }).withMessage('금액은 숫자여야 합니다.'),
]);

// 1시간마다 만료된 레코드 정리
setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of loginFailMap.entries()) {
        if (now - record.firstFailAt > LOGIN_FAIL_WINDOW) {
            loginFailMap.delete(ip);
        }
    }
}, 60 * 60 * 1000);

module.exports = {
    loginRateLimiter, recordLoginFailure, resetLoginAttempts,
    registerLimiter, registerValidator, loginValidator,
    expenditureValidator, validatePassword
};