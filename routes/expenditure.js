const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const serialize = require('serialize-javascript');
const db = require('../database');
const { uploadDir, upload, saveFile } = require('../helpers/file');
const { getTodayKST, getUser, getUserByPos, getNextDocNum, getSiteUrl, logAction } = require('../helpers/db');
const { makeEmailHtml, sendEmail } = require('../helpers/email');
const { expenditureValidator } = require('../middleware/validators');

router.get('/list', (req, res) => {
    const user = getUser(req);
    let { page = 1, keyword = '', author = '' } = req.query;
    const limit = 10;
    let currentPage = parseInt(page);
    if (isNaN(currentPage) || currentPage < 1) currentPage = 1;
    const offset = (currentPage - 1) * limit;
    const sanitizedKeyword = keyword.replace(/%/g, '').trim();

    db.all("SELECT DISTINCT appName FROM expenditures WHERE appName IS NOT NULL AND appName != '' ORDER BY appName ASC", [], (err, authors) => {
        let whereClause = "WHERE 1=1";
        let params = [];
        if (sanitizedKeyword) {
            whereClause += " AND (subject LIKE ? OR bodyContent LIKE ?)";
            params.push(`%${sanitizedKeyword}%`, `%${sanitizedKeyword}%`);
        }
        if (author) { whereClause += " AND appName = ?"; params.push(author); }

        let authClause = "";
        if (user.role !== 'Admin') {
            authClause = ` AND (applicantEmail = ? OR status IN ('최종결재', '지급완료') OR (status = '제출완료' AND ? = '사무총장') OR (status = '결재중' AND ? = '총동문회장'))`;
        }
        const countParams = user.role !== 'Admin' ? [...params, user.email, user.position, user.position] : params;

        db.get(`SELECT COUNT(*) as total FROM expenditures ${whereClause} ${authClause}`, countParams, (err, countRow) => {
            const totalDocs = countRow ? countRow.total : 0;
            const totalPages = Math.ceil(totalDocs / limit);
            const finalQuery = `
                SELECT *,
                (
                    (applicantEmail = ? AND (status = '작성중' OR status = '반려')) OR
                    (? = '사무총장' AND status = '제출완료') OR
                    (? = '총동문회장' AND status = '결재중') OR
                    (? = '재무국장' AND status = '최종결재')
                ) as spotlight
                FROM expenditures ${whereClause} ${authClause}
                ORDER BY spotlight DESC,
                    CASE status
                        WHEN '결재중' THEN 1 WHEN '제출완료' THEN 2 WHEN '작성중' THEN 3
                        WHEN '반려' THEN 3 WHEN '최종결재' THEN 4 WHEN '지급완료' THEN 5 ELSE 6
                    END ASC,
                    docNum DESC
                LIMIT ? OFFSET ?`;
            const queryParams = [
                user.email, user.position, user.position, user.position,
                ...params,
                ...(user.role !== 'Admin' ? [user.email, user.position, user.position] : []),
                limit, offset
            ];
            db.all(finalQuery, queryParams, (err, rows) => {
                if (err) console.error("Query Error:", err);
                res.render('ExpenditureList', { user, docs: rows || [], currentPage, totalPages, authors: authors || [], query: { keyword: sanitizedKeyword, author } });
            });
        });
    });
});

router.get('/form', async (req, res) => {
    const user = getUser(req);
    const docNum = req.query.docNum;
    const listPage = req.query.page || 1;
    const listKeyword = req.query.keyword || '';
    const listAuthor = req.query.author || '';
    const listQueryStr = `page=${listPage}&keyword=${encodeURIComponent(listKeyword)}&author=${encodeURIComponent(listAuthor)}`;

    const renderAlertHTML = (msg) => `<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><title>알림</title>
        <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
        <style>body{background-color:#f0f2f5;}</style></head><body>
        <script>document.addEventListener("DOMContentLoaded",function(){Swal.fire({icon:'warning',title:'접근 제한',text:'${msg}',confirmButtonText:'목록으로 돌아가기',confirmButtonColor:'#3085d6',allowOutsideClick:false,allowEscapeKey:false}).then(()=>{location.replace('/list?${listQueryStr}');});});</script></body></html>`;

    let address = "주소 설정 필요";
    let presInfo = { name: "미지정", phone: "" };
    let secInfo  = { name: "미지정", phone: "" };
    try {
        const addrRow = await new Promise(r => db.get("SELECT value FROM settings WHERE key = 'address'", [], (e, row) => r(row)));
        if (addrRow) address = addrRow.value;
        const pres = await getUserByPos('총동문회장');
        if (pres) presInfo = pres;
        const sec = await getUserByPos('사무총장');
        if (sec) secInfo = sec;
    } catch (e) { console.error("Info Load Error", e); }

    const commonData = {
        address,
        president: `${presInfo.name} (${presInfo.phone})`,
        secretary: `${secInfo.name} (${secInfo.phone})`,
        today: getTodayKST()
    };

    if (!docNum) {
        return res.render('ExpenditureForm', { user, mode: 'WRITE', docNum: '', initDataJSON: serialize({}, { isJSON: true }), ...commonData, listPage, listKeyword, listAuthor });
    }

    db.get("SELECT * FROM expenditures WHERE docNum = ?", [docNum], (err, doc) => {
        if (err || !doc) return res.send(renderAlertHTML('존재하지 않거나 삭제된 문서입니다.'));
        if (doc.status === '작성중' && doc.applicantEmail !== user.email) return res.send(renderAlertHTML('기안자에 의해 회수된 문서입니다. 목록을 갱신합니다.'));
        if (doc.locked_at && doc.locked_by_email && doc.locked_by_email !== user.email) {
            const diffMin = (Date.now() - new Date(doc.locked_at).getTime()) / 1000 / 60;
            if (diffMin < 3) {
                const actionMsg = (doc.locked_by_email === doc.applicantEmail) ? "문서를 수정 중입니다." : "결재 진행 중입니다.";
                return res.send(renderAlertHTML(`현재 [${doc.locked_by_name}]님이 ${actionMsg}`));
            }
        }
        try { doc.items = JSON.parse(doc.items || "[]"); } catch(e) { doc.items = []; }
        doc.attachmentIds = doc.file_paths;
        doc.signatures = { applicant: doc.appSig, secretary: doc.secSig, president: doc.presSig };
        doc.applicantName = doc.applicantName || doc.appName;
        doc.applicantPos  = doc.applicantPos  || doc.appPos;
        doc.applicantPhone = doc.applicantPhone || doc.appPhone;
        let mode = 'VIEW';
        if (doc.applicantEmail === user.email && ['작성중', '반려'].includes(doc.status)) mode = 'WRITE';
        res.render('ExpenditureForm', { user, mode, docNum, initDataJSON: serialize(doc, { isJSON: true }), ...commonData, listPage, listKeyword, listAuthor });
    });
});

const uploadMiddleware = upload.array('newAttachments');

router.post('/api/submit', (req, res, next) => {
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

    if (initialStatus === '제출완료') {
        if (user.position === '사무총장') {
            initialStatus = '결재중';
        } else if (user.position === '총동문회장') {
            initialStatus = '최종결재';
            try { finalDocNum = await getNextDocNum(new Date().getFullYear()); } catch(e) { console.error("DocNum Error:", e); }
        }
    }

    const uploadedFiles = req.files || [];
    const renamedFilePaths = [];
    try {
        let filePaths = [];
        if (f.existingFileIds) filePaths = f.existingFileIds.split(',').filter(x => x);
        const { fileTypeFromFile } = await import('file-type');
        if (uploadedFiles.length > 0) {
            const timestamp = Date.now();
            const ALLOWED_EXTS = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf'];
            for (let i = 0; i < uploadedFiles.length; i++) {
                const file = uploadedFiles[i];
                const detectedType = await fileTypeFromFile(file.path);
                if (!detectedType || !ALLOWED_EXTS.includes(detectedType.ext)) {
                    await fs.promises.unlink(file.path).catch(() => {});
                    throw new Error(`허용되지 않은 파일 형식: ${file.originalname}`);
                }
                const dirName = path.dirname(file.path);
                const finalFilename = `${finalDocNum}_증빙${filePaths.length + 1}_${timestamp}_${i}.${detectedType.ext}`;
                const finalPath = path.join(dirName, finalFilename);
                await fs.promises.rename(file.path, finalPath);
                renamedFilePaths.push(finalPath);
                filePaths.push(path.relative(uploadDir, finalPath).replace(/\\/g, '/'));
            }
        }
        const filePathsStr = filePaths.join(",");
        let itemsStr = f.items;
        try { if (typeof f.items !== 'string') itemsStr = JSON.stringify(f.items); } catch(e) { itemsStr = "[]"; }

        const params = [finalDocNum, user.email, f.subject, f.bodyContent, f.totalAmount, f.executionDate, finalReqDate, itemsStr, initialStatus, user.position, user.name, user.phone, user.signature_path, filePathsStr];

        const afterSave = async () => {
            db.run("UPDATE expenditures SET locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE docNum=?", [finalDocNum]);
            let msg = "제출되었습니다.";
            if (initialStatus === '작성중') msg = "임시저장 되었습니다.";
            else if (initialStatus === '결재중') msg = "제출 및 사무총장 자동 승인 완료 (총동문회장 결재 단계).";
            else if (initialStatus === '최종결재') msg = "제출 및 최종 승인 완료 (재무국장 지급 단계).";
            res.json({ msg });
            try {
                const baseUrl = await getSiteUrl();
                const appInfoStr = `${user.position} ${user.name}`;
                let targetPos = "";
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

        db.get("SELECT docNum FROM expenditures WHERE docNum = ?", [finalDocNum], (err, row) => {
            if (row) {
                db.run("UPDATE expenditures SET subject=?, bodyContent=?, totalAmount=?, executionDate=?, reqDate=?, items=?, status=?, file_paths=? WHERE docNum=?",
                    [f.subject, f.bodyContent, f.totalAmount, f.executionDate, finalReqDate, itemsStr, initialStatus, filePathsStr, finalDocNum],
                    (err) => err ? res.json({ msg: err.message }) : afterSave());
            } else {
                db.run(`INSERT INTO expenditures (docNum, applicantEmail, subject, bodyContent, totalAmount, executionDate, reqDate, items, status, appPos, appName, appPhone, appSig, file_paths, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
                    params, (err) => err ? res.json({ msg: "DB 오류: " + err.message }) : afterSave());
            }
        });
    } catch(e) {
        for (const p of renamedFilePaths) await fs.promises.unlink(p).catch(() => {});
        for (const uf of uploadedFiles) await fs.promises.unlink(uf.path).catch(() => {});
        res.json({ status: 'Error', msg: e.toString() });
    }
});

router.post('/api/approve', (req, res) => {
    const user = getUser(req);
    const { docNum, action } = req.body;
    const todayStr = getTodayKST();

    db.get("SELECT * FROM expenditures WHERE docNum = ?", [docNum], async (err, doc) => {
        if (!doc) return res.json({ msg: "문서를 찾을 수 없습니다." });

        if (action === 'REJECT') {
            logAction(req, 'DOC_REJECT', `문서 반려 처리: ${docNum}`);
            db.run("UPDATE expenditures SET status='반려', locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE docNum=?", [docNum], async () => {
                res.json({ msg: "반려되었습니다." });
                if (doc.applicantEmail) {
                    try {
                        const baseUrl = await getSiteUrl();
                        const appInfo = `${doc.appPos || doc.applicantPos} ${doc.appName || doc.applicantName}`;
                        await sendEmail(doc.applicantEmail, `[반려] ${doc.subject}`, makeEmailHtml(docNum, doc.subject, appInfo, "반려 알림", baseUrl));
                    } catch(e) {}
                }
            });
            return;
        }

        let nextStatus = "", updateQuery = "", params = [], newDocNum = docNum, nextRole = "";

        if (user.position === '사무총장') {
            nextStatus = '결재중'; nextRole = '총동문회장';
            updateQuery = "UPDATE expenditures SET status=?, secName=?, secSig=?, secDate=? WHERE docNum=?";
            params = [nextStatus, user.name, user.signature_path, todayStr, docNum];
        } else if (user.position === '총동문회장') {
            nextStatus = '최종결재'; nextRole = '재무국장';
            try { newDocNum = await getNextDocNum(new Date().getFullYear()); } catch(e) {
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
                        let oldName = oldFiles[index].trim();
                        if (!oldName) continue;
                        const oldPath = path.join(uploadDir, oldName);
                        const fileDir = path.dirname(oldName);
                        const ext = path.extname(oldName);
                        const newFileNameOnly = `${newDocNum}_증빙${index + 1}_${timestamp}${ext}`;
                        const newPath = path.join(uploadDir, fileDir, newFileNameOnly);
                        const newDbPath = path.join(fileDir, newFileNameOnly).replace(/\\/g, '/');
                        try {
                            await fs.promises.access(oldPath);
                            await fs.promises.rename(oldPath, newPath);
                            renameHistory.push({ oldPath, newPath });
                            renamedFiles.push(newDbPath);
                        } catch { console.warn(`File rename warning: ${oldName} not found.`); renamedFiles.push(oldName); }
                    }
                    newFilePaths = renamedFiles.join(',');
                } catch (fileErr) {
                    for (const h of renameHistory) await fs.promises.rename(h.newPath, h.oldPath).catch(() => {});
                    return res.json({ msg: "처리 중 오류가 발생하여 취소되었습니다." });
                }
            }
            db.run("UPDATE expenditures SET docNum=?, status=?, presName=?, presSig=?, presDate=?, presidentSignedDate=?, file_paths=? WHERE docNum=?",
                [newDocNum, nextStatus, user.name, user.signature_path, todayStr, todayStr, newFilePaths, docNum],
                async function(err) {
                    if (err) {
                        for (const h of renameHistory) await fs.promises.rename(h.newPath, h.oldPath).catch(() => {});
                        return res.json({ msg: "DB 저장 오류로 승인이 취소되었습니다.<br>관리자에게 문의하시기 바랍니다." });
                    }
                    logAction(req, 'DOC_APPROVE', `문서 승인(${nextStatus}): ${newDocNum}`);
                    db.run("UPDATE expenditures SET locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE docNum=?", [newDocNum]);
                    res.json({ msg: "승인 완료" });
                    try {
                        const baseUrl = await getSiteUrl();
                        const appInfo = `${doc.appPos || doc.applicantPos} ${doc.appName || doc.applicantName}`;
                        const nextPerson = await getUserByPos(nextRole);
                        if (nextPerson && nextPerson.email) await sendEmail(nextPerson.email, `[결재요청] ${doc.subject}`, makeEmailHtml(newDocNum, doc.subject, appInfo, "결재 요청", baseUrl));
                    } catch(e) {}
                });
            return;
        } else if (user.position === '재무국장') {
            nextStatus = '지급완료';
            updateQuery = "UPDATE expenditures SET status=?, payDate=? WHERE docNum=?";
            params = [nextStatus, todayStr, docNum];
        }

        if (!updateQuery) return res.json({ msg: "승인 권한이 없습니다." });

        db.run(updateQuery, params, async (err) => {
            if (err) return res.json({ msg: err.message });
            logAction(req, 'DOC_APPROVE', `문서 승인(${nextStatus}): ${newDocNum}`);
            db.run("UPDATE expenditures SET locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE docNum=?", [newDocNum]);
            res.json({ msg: "승인 완료" });
            try {
                const baseUrl = await getSiteUrl();
                const appInfo = `${doc.appPos || doc.applicantPos} ${doc.appName || doc.applicantName}`;
                if (nextStatus === '지급완료') {
                    if (doc.applicantEmail) await sendEmail(doc.applicantEmail, `[지급완료] ${doc.subject}`, makeEmailHtml(newDocNum, doc.subject, appInfo, "지급 완료", baseUrl));
                } else {
                    const nextPerson = await getUserByPos(nextRole);
                    if (nextPerson && nextPerson.email) await sendEmail(nextPerson.email, `[결재요청] ${doc.subject}`, makeEmailHtml(newDocNum, doc.subject, appInfo, "결재 요청", baseUrl));
                }
            } catch(e) {}
        });
    });
});

router.get('/profile', (req, res) => {
    const user = getUser(req);
    db.get("SELECT * FROM users WHERE email = ?", [user.email], (err, row) => {
        if (err || !row) return res.redirect('/login');
        delete row.password;
        res.render('profile', { user: row, userDataJSON: serialize(row, { isJSON: true }) });
    });
});

router.post('/api/profile/update', async (req, res) => {
    const user = getUser(req);
    // [보안] position·role 변경은 관리자 전용(admin.js)에서만 허용.
    //        본인 수정 API에서는 의도적으로 수신하지 않는다.
    const { name, generation, phone, password, signatureFile } = req.body;
    let query = "UPDATE users SET name=?, generation=?, phone=?";
    let params = [name, generation, phone];
    if (password) { const hash = await bcrypt.hash(password, 10); query += ", password=?"; params.push(hash); }
    if (signatureFile && signatureFile.data) { const fname = await saveFile(signatureFile.data, signatureFile.type, 'SIG'); query += ", signature_path=?"; params.push(fname); }
    query += " WHERE email=?";
    params.push(user.email);
    db.run(query, params, (err) => {
        if (err) return res.json({ status: 'Error', msg: err.message });
        db.get("SELECT * FROM users WHERE email = ?", [user.email], (err, updatedUser) => {
            req.session.user = updatedUser;
            req.session.save();
            logAction(req, 'UPDATE_PROFILE', `본인 정보 수정: ${name}`);
            res.json({ status: 'Success', msg: '수정되었습니다.' });
        });
    });
});

router.post('/api/lock/acquire', (req, res) => {
    const timeout = new Date(Date.now() - 3 * 60 * 1000).toISOString();
    db.run("UPDATE expenditures SET locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE locked_at < ?", [timeout]);
    const user = getUser(req);
    const { docNum } = req.body;
    db.get("SELECT status, applicantEmail, locked_by_name, locked_by_email, locked_at FROM expenditures WHERE docNum = ?", [docNum], (err, row) => {
        if (err || !row) return res.json({ status: 'Error', msg: '문서가 없습니다.' });
        if (['최종결재', '지급완료'].includes(row.status)) return res.json({ status: 'Success', message: 'Read-only mode (No lock required)' });
        if (row.status === '작성중' && user.email !== row.applicantEmail) return res.json({ status: 'Recalled', msg: '기안자에 의해 회수된 문서입니다.' });
        if (row.locked_at && row.locked_by_email && row.locked_by_email !== user.email) {
            const diffMin = (Date.now() - new Date(row.locked_at).getTime()) / 1000 / 60;
            if (diffMin < 3) {
                const actionMsg = (row.locked_by_email === row.applicantEmail) ? "문서를 수정 중입니다." : "결재 진행 중입니다.";
                return res.json({ status: 'Locked', msg: `현재 [${row.locked_by_name}]님이 ${actionMsg}` });
            }
        }
        db.run("UPDATE expenditures SET locked_by_name=?, locked_by_email=?, locked_at=? WHERE docNum=?",
            [user.name, user.email, new Date().toISOString(), docNum],
            (err) => err ? res.json({ status: 'Error', msg: err.message }) : res.json({ status: 'Success' }));
    });
});

router.post('/api/lock/release', (req, res) => {
    const user = getUser(req);
    const { docNum } = req.body;
    db.run("UPDATE expenditures SET locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE docNum=? AND locked_by_email=?",
        [docNum, user.email],
        function(err) { res.json(err ? { status: 'Error' } : { status: 'Success' }); }
    );
});

router.post('/api/recall', (req, res) => {
    const user = getUser(req);
    const { docNum } = req.body;
    db.run(`UPDATE expenditures SET status='작성중', secName=NULL, secSig=NULL, secDate=NULL, presName=NULL, presSig=NULL, presDate=NULL, presidentSignedDate=NULL, locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE docNum=? AND applicantEmail=? AND status IN ('제출완료', '결재중')`,
        [docNum, user.email], function(err) {
            if (err) return res.json({ status: 'Error', msg: err.message });
            if (this.changes === 0) return res.json({ status: 'Error', msg: '회수할 수 없는 상태입니다.' });
            res.json({ status: 'Success', msg: '문서가 회수되었습니다.' });
        });
});

router.get('/api/download/*', (req, res) => {
    const user = getUser(req);
    const relativePath = req.params[0];
    const safePath = path.resolve(uploadDir, relativePath);
    if (!safePath.startsWith(uploadDir)) {
        console.warn(`[Security] Path Traversal Attempt Blocked: ${req.ip} - ${relativePath}`);
        return res.status(403).send('잘못된 경로 (Access Denied)');
    }
    if (relativePath.startsWith('signatures/') || relativePath.startsWith('signatures\\')) {
        return fs.access(safePath, fs.constants.F_OK, (err) => {
            if (err) return res.status(404).send('서명 파일을 찾을 수 없습니다.');
            res.download(safePath);
        });
    }
    db.get("SELECT applicantEmail, status FROM expenditures WHERE file_paths LIKE ?", [`%${relativePath}%`], async (err, row) => {
        if (err) return res.status(500).send("시스템 오류");
        if (!row) {
            if (user.role !== 'Admin') return res.status(403).send('권한이 없습니다 (문서 정보 없음).');
        } else {
            const isPublicStatus  = ['최종결재', '지급완료'].includes(row.status);
            const isOwnerOrAdmin  = (row.applicantEmail === user.email) || (user.role === 'Admin');
            const isApprover      = ['사무총장', '총동문회장', '재무국장'].includes(user.position);
            if (!isPublicStatus && !isOwnerOrAdmin && !isApprover) return res.status(403).send('권한이 없습니다 (결재 진행 중인 타인의 문서).');
        }
        try { await fs.promises.access(safePath); res.download(safePath); } catch { res.status(404).send('파일 없음'); }
    });
});

router.post('/api/file/delete', async (req, res) => {
    const user = req.session.user;
    if (!user) return res.json({ status: 'Error', msg: '로그인이 필요합니다.' });
    const fileId = req.body.fileId;
    if (!fileId) return res.json({ status: 'Error', msg: '파일 ID가 없습니다.' });
    const safePath = path.resolve(uploadDir, fileId);
    if (!safePath.startsWith(uploadDir + path.sep) && safePath !== uploadDir) {
        console.warn(`[Security] File Delete Path Traversal Attempt: ${req.ip} - ${fileId}`);
        return res.json({ status: 'Error', msg: '잘못된 파일 경로입니다.' });
    }
    try { await fs.promises.unlink(safePath); } catch (e) { console.error("File Delete Error (Ignored):", e.message); }
    db.get("SELECT docNum, file_paths FROM expenditures WHERE file_paths LIKE ?", [`%${fileId}%`], (err, row) => {
        if (err || !row) return res.json({ status: 'Success', msg: '파일이 삭제되었습니다.' });
        const paths = row.file_paths.split(',').map(s => s.trim()).filter(p => p !== fileId && p !== "");
        db.run("UPDATE expenditures SET file_paths = ? WHERE docNum = ?", [paths.join(','), row.docNum], (updateErr) => {
            if (updateErr) return res.json({ status: 'Error', msg: 'DB 업데이트 실패' });
            res.json({ status: 'Success', msg: '파일 및 DB 기록이 삭제되었습니다.' });
        });
    });
});

module.exports = router;