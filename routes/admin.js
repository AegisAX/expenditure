const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const db = require('../database');
const { logAction, getSettings, saveSettings } = require('../helpers/db');
const { uploadDir, saveFile } = require('../helpers/file');
const { requireAdmin } = require('../middleware/auth');
const { validatePassword } = require('../middleware/validators');
const { reloadTransporter, sendEmail, getCurrentMailSettings } = require('../helpers/email');

router.get('/admin', requireAdmin, (req, res) => res.render('admin'));

// [A-3] 설정 조회: 기본 정보 + SMTP 설정(비밀번호는 마스킹)
router.get('/api/admin/settings', requireAdmin, async (req, res) => {
    try {
        const keys = [
            'address', 'admin_phone', 'site_url',
            'smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'mail_from_name'
        ];
        const s = await getSettings(keys);
        const hasPass = !!s.smtp_pass;
        res.json({
            address:        s.address || '',
            admin_phone:    s.admin_phone || '',
            site_url:       s.site_url || '',
            smtp_host:      s.smtp_host || '',
            smtp_port:      s.smtp_port || '',
            smtp_user:      s.smtp_user || '',
            // 실제 비밀번호는 클라이언트로 내보내지 않음.
            // 값이 저장되어 있으면 '********' 자리표시자만 반환.
            smtp_pass:      hasPass ? '********' : '',
            mail_from_name: s.mail_from_name || ''
        });
    } catch (e) {
        res.status(500).json({ status: 'Error', msg: e.message });
    }
});

// [A-3] 설정 저장: 기본 정보 + SMTP. smtp_pass='********'는 변경 없음으로 처리.
// SMTP 관련 키가 변경된 경우에만 transporter 재생성.
router.post('/api/admin/settings', requireAdmin, async (req, res) => {
    try {
        const body = req.body || {};
        const toSave = {};

        // 기본 정보 3종 — 제공된 경우만 저장
        if (body.address !== undefined)     toSave.address     = String(body.address).trim();
        if (body.admin_phone !== undefined) toSave.admin_phone = String(body.admin_phone).trim();
        if (body.site_url !== undefined) {
            // 기존 로직과 동일: 앞뒤 공백 제거 + 끝의 슬래시(중복 포함) 제거
            toSave.site_url = String(body.site_url).trim().replace(/\/+$/, '');
        }

        // SMTP 4종 + 표시명 — 제공된 경우만 저장
        ['smtp_host', 'smtp_port', 'smtp_user', 'mail_from_name'].forEach(k => {
            if (body[k] !== undefined) toSave[k] = String(body[k]).trim();
        });

        // smtp_pass: '********' 이면 기존값 유지(스킵), 그 외에는 그대로 저장.
        // 빈 문자열 저장 시 = 비밀번호 제거 의도(관리자가 의도적으로 비움).
        if (body.smtp_pass !== undefined && body.smtp_pass !== '********') {
            toSave.smtp_pass = String(body.smtp_pass);
        }

        await saveSettings(toSave);

        // SMTP 관련 키가 하나라도 포함되어 있으면 transporter 재생성
        const MAIL_KEYS = ['smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'mail_from_name'];
        const mailKeysChanged = MAIL_KEYS.some(k => Object.prototype.hasOwnProperty.call(toSave, k));
        if (mailKeysChanged) {
            await reloadTransporter();
        }

        // 감사로그: 변경된 "키 이름"만 기록(값은 기록하지 않음 — 비밀번호 유출 방지)
        logAction(req, 'ADMIN_SETTINGS_UPDATE',
            `설정 변경 (${Object.keys(toSave).join(', ') || '없음'})`);

        res.json({ status: 'Success', msg: '설정이 저장되었습니다.' });
    } catch (e) {
        res.status(500).json({ status: 'Error', msg: e.message });
    }
});

// [A-3] 테스트 메일 발송. 수신자 = 로그인한 관리자 본인.
// 현재 transporter(= 저장된 설정 기준)로 실제 발송을 시도한다.
// sendEmail은 fire-and-forget 이므로 응답은 "요청 수락"까지만 보장한다.
router.post('/api/admin/settings/test-mail', requireAdmin, (req, res) => {
    const user = req.session.user;
    if (!user || !user.email) {
        return res.status(400).json({ status: 'Error', msg: '관리자 이메일을 찾을 수 없습니다.' });
    }

    const current = getCurrentMailSettings();
    if (!current.smtp_host || !current.smtp_user || !current.smtp_pass) {
        return res.status(400).json({
            status: 'Error',
            msg: 'SMTP 설정이 완료되지 않았습니다. 호스트/계정/비밀번호를 먼저 저장해 주세요.'
        });
    }

    const now = new Date().toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' });
    const escape = (s) => String(s || '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

    const html =
        '<div style="font-family:\'Malgun Gothic\',\'맑은 고딕\',sans-serif;max-width:520px;margin:0 auto;padding:20px;border:1px solid #e0e0e0;border-radius:8px;">' +
            '<h2 style="color:#2c3e50;border-bottom:2px solid #2c3e50;padding-bottom:8px;">전자결재 메일 설정 테스트</h2>' +
            '<p style="font-size:15px;color:#333;">본 메일은 관리자 설정 화면에서 발송된 <b>테스트 메일</b>입니다.</p>' +
            '<table style="width:100%;font-size:14px;color:#444;margin:16px 0;">' +
                '<tr><td style="padding:6px 0;width:110px;color:#888;">발송 시각</td><td>' + escape(now) + '</td></tr>' +
                '<tr><td style="padding:6px 0;color:#888;">SMTP 호스트</td><td>' + escape(current.smtp_host) + ':' + escape(current.smtp_port) + '</td></tr>' +
                '<tr><td style="padding:6px 0;color:#888;">발신 계정</td><td>' + escape(current.smtp_user) + '</td></tr>' +
                '<tr><td style="padding:6px 0;color:#888;">표시명</td><td>' + escape(current.mail_from_name || '(미설정)') + '</td></tr>' +
            '</table>' +
            '<p style="margin-top:24px;font-size:12px;color:#999;">이 메일을 수신하셨다면 SMTP 설정이 정상 동작하는 것입니다.</p>' +
        '</div>';

    try {
        sendEmail(user.email, '[테스트] 금오공고 총동문회 전자결재 메일 설정 확인', html);
        logAction(req, 'ADMIN_SETTINGS_TEST_MAIL', `테스트 메일 발송 요청: ${user.email}`);
        res.json({
            status: 'Success',
            msg: `${user.email} 로 테스트 메일을 발송 요청했습니다. 수신을 확인해 주세요.`
        });
    } catch (e) {
        res.status(500).json({ status: 'Error', msg: '테스트 메일 발송 중 오류: ' + e.message });
    }
});

router.post('/api/admin/user/unlock', requireAdmin, (req, res) => {
    db.run("UPDATE users SET login_fail_count = 0, locked_until = NULL WHERE id = ?", [req.body.id], (err) => {
        if (err) return res.json({ status: 'Error', msg: err.message });
        res.json({ status: 'Success', msg: '잠금이 해제되었습니다.' });
    });
});

router.post('/api/admin/user/delete', requireAdmin, (req, res) => {
    db.run("DELETE FROM users WHERE id = ?", [req.body.id], (err) => {
        if (err) return res.json({ status: 'Error', msg: err.message });
        res.json({ status: 'Success', msg: '사용자가 삭제되었습니다.' });
    });
});

router.post('/api/admin/user/update', requireAdmin, (req, res) => {
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
            // [수정] 비밀번호 복잡도 검증
            const pwErr = validatePassword(newPassword);
            if (pwErr) return res.json({ status: 'Error', msg: pwErr });
            const hash = await bcrypt.hash(newPassword, 10);
            query += ", password=?";
            params.push(hash);
            changes.push("비밀번호: 변경됨");
        }
        if (signatureFile && signatureFile.data) { const fname = await saveFile(signatureFile.data, signatureFile.type, 'SIG'); query += ", signature_path=?"; params.push(fname); changes.push("서명: 변경됨"); }
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

router.post('/api/admin/user/approve', requireAdmin, (req, res) => {
    db.run("UPDATE users SET status = 'Approved' WHERE id = ?", [req.body.id], (err) => {
        if (!err) logAction(req, 'ADMIN_USER_APPROVE', `사용자 가입 승인 (대상ID: ${req.body.id})`);
        res.json({ status: 'Success', msg: '승인되었습니다.' });
    });
});

router.get('/api/admin/users', requireAdmin, (req, res) => {
    db.all("SELECT id, email, name, position, phone, signature_path, status, generation, role, login_fail_count, locked_until, created_at FROM users ORDER BY created_at DESC",
        [], (err, rows) => res.json(rows || []));
});

router.get('/api/admin/list', requireAdmin, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    const keyword = req.query.keyword || '';
    let whereClause = "WHERE 1=1";
    let params = [];
    if (keyword) { whereClause += " AND (docNum LIKE ? OR subject LIKE ? OR appName LIKE ?)"; const k = `%${keyword}%`; params.push(k, k, k); }
    db.get(`SELECT COUNT(*) as count FROM expenditures ${whereClause}`, params, (err, countRow) => {
        if (err) return res.json({ docs: [], total: 0 });
        db.all(`SELECT * FROM expenditures ${whereClause} ORDER BY docNum DESC LIMIT ? OFFSET ?`, [...params, limit, offset], (err, rows) => {
            if (err) return res.json({ docs: [], total: 0 });
            res.json({ docs: rows.map(doc => ({ docNum: doc.docNum, subject: doc.subject, applicant: doc.appName || '-', stage: doc.status })), total: countRow.count, page, totalPages: Math.ceil(countRow.count / limit) });
        });
    });
});

router.post('/api/admin/delete_doc', requireAdmin, (req, res) => {
    const { docNum } = req.body;
    db.get("SELECT file_paths FROM expenditures WHERE docNum = ?", [docNum], async (err, row) => {
        if (err) return res.json({ status: 'Error', msg: 'DB 조회 실패' });
        if (!row) return res.json({ status: 'Error', msg: '문서가 존재하지 않습니다.' });
        if (row.file_paths) {
            for (const fileName of row.file_paths.split(',')) {
                try { await fs.promises.unlink(path.join(uploadDir, fileName.trim())); } catch (e) { console.error(`[Admin] 파일 삭제 실패: ${fileName}`, e.message); }
            }
        }
        db.run("DELETE FROM expenditures WHERE docNum = ?", [docNum], (err) => {
            if (err) return res.json({ status: 'Error', msg: err.message });
            logAction(req, 'DELETE_DOC', `문서 영구 삭제: ${docNum}`);
            res.json({ status: 'Success', msg: '삭제되었습니다.' });
        });
    });
});

router.get('/api/admin/logs', requireAdmin, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 15;
    const offset = (page - 1) * limit;
    const keyword = req.query.keyword || '';
    let whereClause = "WHERE 1=1";
    let params = [];
    if (keyword) { whereClause += " AND (user_name LIKE ? OR action LIKE ? OR details LIKE ? OR ip_address LIKE ?)"; const k = `%${keyword}%`; params.push(k, k, k, k); }
    db.get(`SELECT COUNT(*) as count FROM audit_logs ${whereClause}`, params, (err, countRow) => {
        if (err) return res.json({ logs: [], total: 0 });
        db.all(`SELECT * FROM audit_logs ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`, [...params, limit, offset], (err, rows) => {
            res.json({ logs: rows || [], total: countRow.count, page, totalPages: Math.ceil(countRow.count / limit) });
        });
    });
});

module.exports = router;