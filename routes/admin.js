const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const db = require('../database');
const { logAction, getSettings, saveSettings, getUserByPos, getSiteUrl } = require('../helpers/db');
const { uploadDir, saveFile } = require('../helpers/file');
const { requireAdmin } = require('../middleware/auth');
const { validatePassword } = require('../middleware/validators');
const { reloadTransporter, sendEmail, getCurrentMailSettings, makeEmailHtml } = require('../helpers/email');

router.get('/admin', requireAdmin, (req, res) => res.render('admin', { user: req.session.user }));

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
router.post('/api/admin/settings/test-mail', requireAdmin, async (req, res) => {
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
        // [개선] sendEmail 결과를 await 하여 실제 발송 성공/실패 분기
        const result = await sendEmail(
            user.email,
            '[테스트] 금오공고 총동문회 전자결재 메일 설정 확인',
            html
        );

        if (result.success) {
            logAction(req, 'ADMIN_SETTINGS_TEST_MAIL', `테스트 메일 발송 성공: ${user.email}`);
            return res.json({
                status: 'Success',
                msg: `${user.email} 로 테스트 메일이 발송되었습니다. 수신을 확인해 주세요.`
            });
        } else {
            logAction(req, 'ADMIN_SETTINGS_TEST_MAIL_FAIL', `테스트 메일 발송 실패: ${user.email} (${result.error})`);
            return res.json({
                status: 'Error',
                msg: '테스트 메일 발송에 실패했습니다.\n사유: ' + result.error
            });
        }
    } catch (e) {
        console.error('[Test Mail] 예외:', e);
        return res.status(500).json({ status: 'Error', msg: '테스트 메일 발송 중 오류가 발생했습니다: ' + e.message });
    }
});

router.post('/api/admin/user/unlock', requireAdmin, (req, res) => {
    db.run("UPDATE users SET login_fail_count = 0, locked_until = NULL WHERE id = ?", [req.body.id], (err) => {
        if (err) return res.json({ status: 'Error', msg: err.message });
        res.json({ status: 'Success', msg: '잠금이 해제되었습니다.' });
    });
});

router.post('/api/admin/user/delete', requireAdmin, (req, res) => {
    const targetId = req.body.id;
    const myId = req.session.user && req.session.user.id;
    // [개선] 본인 자신은 삭제 못 함
    if (targetId && myId && Number(targetId) === Number(myId)) {
        return res.json({ status: 'Error', msg: '본인 계정은 삭제할 수 없습니다.' });
    }
    db.run("DELETE FROM users WHERE id = ?", [targetId], (err) => {
        if (err) return res.json({ status: 'Error', msg: err.message });
        res.json({ status: 'Success', msg: '사용자가 삭제되었습니다.' });
    });
});

// [SECURITY] 직책 문자열이 '~장' 으로 끝나는지 (실장/회장/국장 등 모든 '장' 직책)
function isLeaderPosition(pos) {
    return typeof pos === 'string' && pos.length > 1 && pos.endsWith('장');
}

// 같은 대수 + 같은 '~장' 직책에 다른 사용자가 이미 있는지 검사.
// excludeId: 자기 자신은 제외.
// 결과: 충돌 발견 시 충돌 사용자 정보, 없으면 null
function checkLeaderPositionConflict(generation, position, excludeId) {
    return new Promise((resolve, reject) => {
        if (!isLeaderPosition(position)) return resolve(null);
        if (generation == null || generation === '') return resolve(null);
        const sql = "SELECT id, email, name FROM users WHERE generation = ? AND position = ? AND id != ? LIMIT 1";
        db.get(sql, [generation, position, excludeId || 0], (err, row) => {
            if (err) return reject(err);
            resolve(row || null);
        });
    });
}

router.post('/api/admin/user/update', requireAdmin, (req, res) => {
    const { id, email, name, position, phone, generation, status, role, newPassword, signatureFile } = req.body;
    db.get("SELECT * FROM users WHERE id = ?", [id], async (err, oldUser) => {
        if (err || !oldUser) return res.json({ status: 'Error', msg: '사용자를 찾을 수 없습니다.' });

        // [B-fix] '~장' 직책 중복 검사 (같은 대수에서 1명만)
        try {
            const conflict = await checkLeaderPositionConflict(generation, position, id);
            if (conflict) {
                return res.json({
                    status: 'Error',
                    msg: `같은 대수(${generation}대)에 이미 '${position}' 직책의 사용자가 있습니다: ${conflict.name} (${conflict.email})`
                });
            }
        } catch (e) {
            return res.json({ status: 'Error', msg: '직책 중복 확인 실패: ' + e.message });
        }

        // [B-fix] 이메일 변경 처리 (입력값 trim, 형식 검증, UNIQUE 충돌 사전 검사)
        let newEmail = (email || '').trim();
        if (!newEmail) return res.json({ status: 'Error', msg: '이메일은 필수입니다.' });
        const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRe.test(newEmail)) return res.json({ status: 'Error', msg: '이메일 형식이 올바르지 않습니다.' });

        if (newEmail !== oldUser.email) {
            // 다른 사용자가 이미 사용 중인지 확인
            try {
                await new Promise((resolve, reject) => {
                    db.get("SELECT id FROM users WHERE email = ? AND id != ?", [newEmail, id], (e, row) => {
                        if (e) return reject(e);
                        if (row) return reject(new Error(`이미 사용 중인 이메일입니다: ${newEmail}`));
                        resolve();
                    });
                });
            } catch (e) {
                return res.json({ status: 'Error', msg: e.message });
                // try/catch 의 return 은 외부 함수를 정상적으로 종료시킴
            }
        }

        let query = "UPDATE users SET email=?, name=?, position=?, phone=?, generation=?, status=?, role=?";
        let params = [newEmail, name, position, phone, generation, status, role];
        let changes = [];
        if (oldUser.email != newEmail) changes.push(`이메일: ${oldUser.email} -> ${newEmail}`);
        if (oldUser.name != name) changes.push(`이름: ${oldUser.name} -> ${name}`);
        if (oldUser.position != position) changes.push(`직책: ${oldUser.position} -> ${position}`);
        if (oldUser.phone != phone) changes.push(`전화: ${oldUser.phone} -> ${phone}`);
        if (oldUser.generation != generation) changes.push(`대수: ${oldUser.generation} -> ${generation}`);
        if (oldUser.status != status) changes.push(`상태: ${oldUser.status} -> ${status}`);
        if (oldUser.role != role) changes.push(`권한: ${oldUser.role} -> ${role}`);

        if (newPassword) {
            const pwErr = validatePassword(newPassword);
            if (pwErr) return res.json({ status: 'Error', msg: pwErr });
            const hash = await bcrypt.hash(newPassword, 10);
            query += ", password=?";
            params.push(hash);
            changes.push("비밀번호: 변경됨");
        }
        if (signatureFile && signatureFile.data) { 
            const fname = await saveFile(signatureFile.data, signatureFile.type, 'SIG'); 
            query += ", signature_path=?"; 
            params.push(fname); 
            changes.push("서명: 변경됨"); 
        }
        query += " WHERE id=?";
        params.push(id);
        db.run(query, params, (updateErr) => {
            if (updateErr) {
                if (/UNIQUE constraint failed: users.email/i.test(updateErr.message)) {
                    return res.json({ status: 'Error', msg: '이미 사용 중인 이메일입니다.' });
                }
                return res.json({ status: 'Error', msg: updateErr.message });
            }
            const logDetail = changes.length > 0
                ? `관리자 정보 수정 (ID: ${id}, 대상: ${oldUser.name}) - [ ${changes.join(', ')} ]`
                : `관리자 정보 수정 (ID: ${id}, 대상: ${oldUser.name}) - 변경 사항 없음`;
            logAction(req, 'ADMIN_USER_UPDATE', logDetail);
            res.json({ status: 'Success', msg: '수정되었습니다.' });
        });
    });
});

router.post('/api/admin/user/approve', requireAdmin, (req, res) => {
    const id = req.body.id;
    // 승인 전에 해당 사용자의 직책/대수 조회
    db.get("SELECT id, generation, position, name, email FROM users WHERE id = ?", [id], async (err, user) => {
        if (err || !user) return res.json({ status: 'Error', msg: '사용자를 찾을 수 없습니다.' });

        // [B-fix] '~장' 직책 중복 검사
        try {
            const conflict = await checkLeaderPositionConflict(user.generation, user.position, user.id);
            if (conflict) {
                return res.json({
                    status: 'Error',
                    msg: `같은 대수(${user.generation}대)에 이미 '${user.position}' 직책의 사용자가 있습니다: ${conflict.name} (${conflict.email}). 직책을 먼저 수정하거나 기존 사용자의 직책을 변경한 후 승인해 주세요.`
                });
            }
        } catch (e) {
            return res.json({ status: 'Error', msg: '직책 중복 확인 실패: ' + e.message });
        }

        db.run("UPDATE users SET status = 'Approved' WHERE id = ?", [id], (uerr) => {
            if (uerr) return res.json({ status: 'Error', msg: uerr.message });
            logAction(req, 'ADMIN_USER_APPROVE', `사용자 가입 승인 (대상ID: ${id}, 직책: ${user.position}/${user.generation}대)`);
            res.json({ status: 'Success', msg: '승인되었습니다.' });
        });
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
    db.get(`SELECT COUNT(*) as count FROM approvals ${whereClause}`, params, (err, countRow) => {
        if (err) return res.json({ docs: [], total: 0 });
        // [관리자 정렬] 일반 목록(/list)의 정렬 규칙을 그대로 적용 (spotlight 만 제외).
        //   - 1단계: 진행 그룹('작성중'/'반려'/'제출완료'/'결재중')을 위로
        //   - 2단계: 같은 그룹 내에서는 docNum 내림차순
        //   '최종결재'는 재무국장 결재 대기 단계지만 일반 목록 기준에서 종결 그룹으로 묶임.
        //   TEMP-* 는 docNum 사전식 비교에서 사무국-* 보다 작아 자연스럽게 진행 그룹 안에서 위로 올라간다.
        const orderClause = `
            ORDER BY
                CASE
                    WHEN status IN ('작성중', '반려', '제출완료', '결재중')
                        THEN 0
                    ELSE 1
                END ASC,
                docNum DESC
        `;
        db.all(`SELECT * FROM approvals ${whereClause} ${orderClause} LIMIT ? OFFSET ?`, [...params, limit, offset], (err, rows) => {
            if (err) return res.json({ docs: [], total: 0 });
            // [B-3] 응답에 docType 추가 — 관리자 화면에서 유형 배지 표시용
            res.json({
                docs: rows.map(doc => ({
                    docNum: doc.docNum,
                    subject: doc.subject,
                    applicant: doc.appName || '-',
                    stage: doc.status,
                    docType: doc.docType || 'E'
                })),
                total: countRow.count,
                page,
                totalPages: Math.ceil(countRow.count / limit)
            });
        });
    });
});

// [STAGE_SKIP] 관리자 문서 상세 조회.
// 관리자 화면(문서 관리 섹션)에서 행 클릭 시 모달 표시용.
// 결재 라인의 현재 상태와 건너뛰기 가능 여부를 함께 반환한다.
router.get('/api/admin/doc/:docNum', requireAdmin, (req, res) => {
    const { docNum } = req.params;
    db.get("SELECT * FROM approvals WHERE docNum = ?", [docNum], (err, doc) => {
        if (err)  return res.status(500).json({ status: 'Error', msg: 'DB 조회 실패: ' + err.message });
        if (!doc) return res.status(404).json({ status: 'Error', msg: '문서를 찾을 수 없습니다.' });

        // 사무총장 건너뛰기 가능 여부 판정 (제출완료 상태 + 아직 안 건너뛴 경우)
        const canSkipSecretary = (doc.status === '제출완료') && !doc.secSkippedBy;

        res.json({
            status: 'Success',
            doc: {
                docNum:           doc.docNum,
                docType:          doc.docType || 'E',
                subject:          doc.subject,
                status:           doc.status,
                applicantEmail:   doc.applicantEmail,
                appName:          doc.appName,
                appPos:           doc.appPos,
                reqDate:          doc.reqDate,
                totalAmount:      doc.totalAmount,
                secName:          doc.secName,
                secDate:          doc.secDate,
                secSkippedBy:     doc.secSkippedBy,
                secSkippedAt:     doc.secSkippedAt,
                secSkippedReason: doc.secSkippedReason,
                presName:         doc.presName,
                executionDate:    doc.executionDate,
                payDate:          doc.payDate
            },
            canSkipSecretary
        });
    });
});

// [STAGE_SKIP] 사무총장 결재 단계 건너뛰기.
// - 권한: Admin 전용
// - 허용 상태: '제출완료' (사무총장 결재 전 단계) 만
// - 사유(reason) 필수 입력
// - 처리: 상태를 '결재중'으로 전이, secSkippedBy/At/Reason 기록, 총동문회장에게 메일
// - 사무총장 결재칸은 화면에서 사선(/)으로 표시 (secSig는 NULL 유지)
router.post('/api/admin/skip-stage', requireAdmin, async (req, res) => {
    const admin = req.session.user;
    const { docNum, reason } = req.body || {};

    if (!docNum) {
        return res.status(400).json({ status: 'Error', msg: '문서 번호가 누락되었습니다.' });
    }
    const trimmedReason = (reason || '').trim();
    if (!trimmedReason) {
        return res.status(400).json({ status: 'Error', msg: '건너뛰기 사유는 필수 입력입니다.' });
    }
    if (trimmedReason.length > 500) {
        return res.status(400).json({ status: 'Error', msg: '건너뛰기 사유는 500자 이내로 입력해 주세요.' });
    }

    // 문서 조회 및 상태 검증
    db.get("SELECT * FROM approvals WHERE docNum = ?", [docNum], async (err, doc) => {
        if (err)  return res.status(500).json({ status: 'Error', msg: 'DB 조회 실패: ' + err.message });
        if (!doc) return res.status(404).json({ status: 'Error', msg: '문서를 찾을 수 없습니다.' });

        if (doc.status !== '제출완료') {
            return res.status(400).json({
                status: 'Error',
                msg: `현재 상태(${doc.status})에서는 사무총장 건너뛰기를 할 수 없습니다.\n'제출완료' 상태의 문서만 가능합니다.`
            });
        }
        if (doc.secSkippedBy) {
            return res.status(400).json({
                status: 'Error',
                msg: '이미 사무총장 결재 단계가 건너뛰기 처리된 문서입니다.'
            });
        }

        // 락 점유 확인 — 다른 사용자가 편집/결재 중이면 거부
        if (doc.locked_at && doc.locked_by_email && doc.locked_by_email !== admin.email) {
            const diffMin = (Date.now() - new Date(doc.locked_at).getTime()) / 1000 / 60;
            if (diffMin < 3) {
                return res.status(409).json({
                    status: 'Error',
                    msg: `현재 [${doc.locked_by_name}]님이 문서를 처리 중입니다.\n잠시 후 다시 시도해 주세요.`
                });
            }
        }

        // 상태 전이 + 건너뛰기 기록
        // secSig 는 NULL 유지 (실제 사무총장 결재가 없었음을 명확히)
        // 화면 표시는 secSkippedBy 가 NULL 이 아닌 것을 기준으로 사선(/) 표시
        const nowIso = new Date().toISOString();
        const sql = `UPDATE approvals SET
                        status = '결재중',
                        secSkippedBy = ?,
                        secSkippedAt = ?,
                        secSkippedReason = ?,
                        locked_by_name = NULL,
                        locked_by_email = NULL,
                        locked_at = NULL
                     WHERE docNum = ? AND status = '제출완료' AND secSkippedBy IS NULL`;
        db.run(sql, [admin.email, nowIso, trimmedReason, docNum], async function(updateErr) {
            if (updateErr) {
                return res.status(500).json({ status: 'Error', msg: 'DB 업데이트 실패: ' + updateErr.message });
            }
            if (this.changes === 0) {
                // 동시성 충돌 (다른 관리자가 먼저 처리했거나 상태가 변경됨)
                return res.status(409).json({
                    status: 'Error',
                    msg: '문서 상태가 변경되어 처리할 수 없습니다. 화면을 새로고침 후 다시 시도해 주세요.'
                });
            }

            logAction(
                req,
                'STAGE_SKIP',
                `사무총장 결재 단계 건너뛰기: ${docNum} - 사유: ${trimmedReason}`
            );

            res.json({
                status: 'Success',
                msg: '사무총장 결재 단계를 건너뛰었습니다. 총동문회장에게 결재 요청 메일이 발송됩니다.'
            });

            // 총동문회장에게 결재 요청 메일 (fire-and-forget)
            try {
                const meta = (doc.docType === 'G')
                    ? { label: '일반 기안' }
                    : { label: '지출결의서' };
                const baseUrl = await getSiteUrl();
                const nextPerson = await getUserByPos('총동문회장');
                if (nextPerson && nextPerson.email) {
                    const appInfo = `${doc.appPos || ''} ${doc.appName || ''}`.trim();
                    // [STAGE_SKIP] 메일 본문에 건너뛰기 사유를 그대로 노출.
                    //              제목과 본문 모두 "사무총장 단계 생략" 표식을 유지하되
                    //              구체적인 사유는 statusMsg 로 전달한다.
                    const statusMsg = `결재 요청 (사무총장 결재 생략 사유: ${trimmedReason})`;
                    await sendEmail(
                        nextPerson.email,
                        `[결재요청] ${meta.label} - ${doc.subject} (사무총장 결재 생략)`,
                        makeEmailHtml(docNum, doc.subject, appInfo, statusMsg, baseUrl)
                    );
                }
            } catch (e) {
                console.error('[Mail dispatch error]', e.message);
            }
        });
    });
});

router.post('/api/admin/delete_doc', requireAdmin, (req, res) => {
    const { docNum } = req.body;
    db.get("SELECT file_paths FROM approvals WHERE docNum = ?", [docNum], async (err, row) => {
        if (err) return res.json({ status: 'Error', msg: 'DB 조회 실패' });
        if (!row) return res.json({ status: 'Error', msg: '문서가 존재하지 않습니다.' });
        if (row.file_paths) {
            for (const fileName of row.file_paths.split(',')) {
                try { await fs.promises.unlink(path.join(uploadDir, fileName.trim())); } catch (e) { console.error(`[Admin] 파일 삭제 실패: ${fileName}`, e.message); }
            }
        }
        db.run("DELETE FROM approvals WHERE docNum = ?", [docNum], (err) => {
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