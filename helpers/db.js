const db = require('../database');

function getTodayKST() {
    const d = new Date();
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function getUser(req) {
    return req.session.user || null;
}

function getUserByPos(position) {
    return new Promise((resolve) => {
        db.get(
            "SELECT email, name, phone, signature_path FROM users WHERE position = ? AND status = 'Approved' ORDER BY created_at DESC LIMIT 1",
            [position],
            (err, row) => { if (err || !row) resolve(null); else resolve(row); }
        );
    });
}

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
    return new Promise((resolve) => {
        db.get("SELECT value FROM settings WHERE key = 'site_url'", [], (e, row) => {
            let url = (row && row.value) ? row.value.trim() : 'http://localhost:8080';
            if (url.endsWith('/')) url = url.slice(0, -1);
            resolve(url);
        });
    });
}

function clearStaleLocks() {
    const timeout = new Date(Date.now() - 30 * 60 * 1000).toISOString();
    db.run("UPDATE expenditures SET locked_by_name=NULL, locked_by_email=NULL, locked_at=NULL WHERE locked_at < ?", [timeout]);
}

function logAction(req, action, details) {
    const user = req.session.user;
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (ip && ip.includes('::ffff:')) ip = ip.split(':').pop();
    db.run(
        `INSERT INTO audit_logs (user_email, user_name, action, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))`,
        [user ? user.email : 'Unknown', user ? user.name : 'System', action, details, ip],
        (err) => { if (err) console.error(err); }
    );
}

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
                db.run(`ALTER TABLE expenditures ADD COLUMN ${col.name} ${col.type}`);
                added++;
            }
        });

        // [통합 마이그레이션] presDate, presidentSignedDate -> executionDate
        // 기존 DB에 presDate 또는 presidentSignedDate 컬럼이 남아 있는 경우,
        // executionDate가 비어 있는 행에 한해 값을 복사한다.
        if (existingNames.includes('presDate')) {
            db.run(`UPDATE expenditures SET executionDate = presDate
                    WHERE (executionDate IS NULL OR executionDate = '')
                      AND presDate IS NOT NULL AND presDate != ''`,
                (e) => {
                    if (!e) console.log(">> [DB Migrate] presDate -> executionDate 복사 완료.");
                });
        }
        if (existingNames.includes('presidentSignedDate')) {
            db.run(`UPDATE expenditures SET executionDate = presidentSignedDate
                    WHERE (executionDate IS NULL OR executionDate = '')
                      AND presidentSignedDate IS NOT NULL AND presidentSignedDate != ''`,
                (e) => {
                    if (!e) console.log(">> [DB Migrate] presidentSignedDate -> executionDate 복사 완료.");
                });
        }

        console.log(`>> [DB Check] 검사 완료. (추가된 컬럼: ${added}개)`);
    });
}

module.exports = { getTodayKST, getUser, getUserByPos, getNextDocNum, getSiteUrl, clearStaleLocks, logAction, checkAndMigrateDB };