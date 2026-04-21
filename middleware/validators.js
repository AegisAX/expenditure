const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { status: 'Fail', msg: '로그인 시도 횟수가 초과되었습니다.<br>15분 후 다시 시도해주세요.' },
    handler: (req, res, next, options) => {
        console.warn(`[Security] Rate Limit Exceeded: ${req.ip}`);
        res.status(options.statusCode).json(options.message);
    }
});

const validate = (validations) => async (req, res, next) => {
    await Promise.all(validations.map(v => v.run(req)));
    const errors = validationResult(req);
    if (errors.isEmpty()) return next();
    return res.json({ status: 'Fail', msg: errors.array()[0].msg });
};

const registerValidator = validate([
    body('email').isEmail().withMessage('유효한 이메일을 입력해주세요.').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('비밀번호는 6자 이상이어야 합니다.'),
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
    body('executionDate').notEmpty().withMessage('시행일자를 선택해주세요.')
]);

module.exports = { authLimiter, registerValidator, loginValidator, expenditureValidator };