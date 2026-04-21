const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const db = require('../database');
const { logAction } = require('../helpers/db');
const { uploadDir, saveFile } = require('../helpers/file');
const { requireAdmin } = require('../middleware/auth');
const { validatePassword } = require('../middleware/validators');

router.get('/admin', requireAdmin, (req, res) => res.render('admin'));

router.get('/api/admin/settings', requireAdmin, (req, res) => {
    db.all("SELECT key, value FROM settings", [], (err, rows) => {
        if (err) return res.json({});
        const settings = {};
        rows.forEach(r => settings[r.key] = r.value);
        res.json(settings);
    });
});

router.post('/api/admin/settings', requireAdmin, (req, res) => {
    const { address, site_url } = req.body;
    db.serialize(() => {
        db.run("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ['address', address]);
        db.run("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ['site_url', site_url], (err) => {
            if (err) res.json({ status: 'Error', msg: err.message });
            else res.json({ status: 'Success', msg: '설정이 저장되었습니다.' });
        });
    });
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
    db.all("SELECT * FROM users ORDER BY created_at DESC", [], (err, rows) => res.json(rows || []));
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