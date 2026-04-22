const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../database');
const { logAction } = require('../helpers/db');
const { saveFile } = require('../helpers/file');
const { loginRateLimiter, recordLoginFailure, resetLoginAttempts, registerLimiter, registerValidator, loginValidator } = require('../middleware/validators');

router.get(['/', '/login', '/register'], (req, res) => {
    if (req.session.user) return res.redirect('/list');
    res.render('register', { targetDocNum: req.query.docNum || '' });
});

router.post('/api/login', loginRateLimiter, loginValidator, (req, res) => {
    const { email, password } = req.body;
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, row) => {
        if (err || !row) {
            recordLoginFailure(req.ip);  // ← 실패 카운트
            return res.json({ status: 'Fail', msg: '정보 불일치' });
        }
        if (row.locked_until && new Date(row.locked_until) > new Date()) {
            // 계정 잠금은 IP 카운터와 무관 — 카운트 증가 안 함
            const remainMs  = new Date(row.locked_until) - new Date();
            const remainMin = Math.ceil(remainMs / 60000);
            return res.json({
                status: 'Fail',
                msg: `계정이 잠겨 있습니다. 약 ${remainMin}분 후 다시 시도해 주세요.`
            });
        }
        if (await bcrypt.compare(password, row.password)) {
            if (row.status !== 'Approved') {
                logAction(req, 'LOGIN_FAIL', `미승인 계정 로그인 시도: ${email}`);
                return res.json({ status: 'Fail', msg: '승인 대기 중' });
            }
            db.run("UPDATE users SET login_fail_count = 0, locked_until = NULL WHERE id = ?", [row.id]);
            resetLoginAttempts(req.ip);  // ← 승인된 사용자만 초기화
            const { password: _pw, ...safeUser } = row;
            req.session.user = safeUser;
            req.session.save();
            logAction(req, 'LOGIN', '로그인 성공');
            res.json({ status: 'Approved', url: '/list' });
        } else {
            recordLoginFailure(req.ip);  // ← 실패 카운트
            logAction(req, 'LOGIN_FAIL', `실패: ${email}`);
            let cnt = (row.login_fail_count || 0) + 1;
            if (cnt >= 5) {
                db.run("UPDATE users SET login_fail_count = ?, locked_until = ? WHERE id = ?",
                    [cnt, new Date(Date.now() + 30 * 60000).toISOString(), row.id]);
                res.json({ status: 'Fail', msg: '로그인 5회 실패로 계정이 30분간 잠겼습니다.' });
            } else {
                db.run("UPDATE users SET login_fail_count = ? WHERE id = ?", [cnt, row.id]);
                res.json({ status: 'Fail', msg: `정보 불일치 (${cnt}/5)` });
            }
        }
    });
});

router.post('/api/register', registerLimiter, registerValidator, async (req, res) => {
    const { email, password, name, position, phone, generation, signatureFile } = req.body;
    try {
        const existingUser = await new Promise((resolve, reject) => {
            db.get("SELECT email FROM users WHERE email = ?", [email], (err, row) => {
                if (err) reject(err); else resolve(row);
            });
        });
        if (existingUser) {
            return res.json({ status: 'Error', msg: '이미 사용 중인 이메일 주소입니다.<br>다른 이메일을 입력해 주세요.' });
        }
        const hash = await bcrypt.hash(password, 10);
        let sigPath = '';
        if (signatureFile && signatureFile.data) {
            sigPath = await saveFile(signatureFile.data, signatureFile.type, 'SIG');
        }
        const insertQuery = `
            INSERT INTO users (email, password, name, position, phone, signature_path, generation, role, status, login_fail_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'User', 'Pending', 0)
        `;
        db.run(insertQuery, [email, hash, name, position, phone, sigPath, generation], (err) => {
            if (err) {
                console.error("Register DB Error:", err);
                return res.json({ status: 'Error', msg: '가입 처리 중 오류가 발생했습니다.<br>잠시 후 다시 시도해 주세요.' });
            }
            res.json({ status: 'Success', msg: '회원가입 신청이 완료되었습니다.<br>관리자 승인 후 로그인 가능합니다.' });
        });
    } catch (e) {
        console.error("Register Error:", e);
        res.json({ status: 'Error', msg: '시스템 오류가 발생했습니다.' });
    }
});

router.get('/api/logout', (req, res) => {
    logAction(req, 'LOGOUT', '로그아웃');
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

module.exports = router;