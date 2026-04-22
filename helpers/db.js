const db = require('../database');

function getTodayKST() {
    // 서버 TZ 설정과 무관하게 항상 KST(UTC+9) 기준으로 날짜 반환
    const d = new Date(Date.now() + 9 * 60 * 60 * 1000);
    return d.toISOString().slice(0, 10);  // "YYYY-MM-DD"
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
        // [수정] 각 단계를 콜백 체인으로 명시적 순서 보장
        //        중간 실패 시 반드시 ROLLBACK 후 reject
        db.run("BEGIN IMMEDIATE", (err) => {
            if (err) return reject(err);

            db.run("INSERT OR IGNORE INTO doc_sequences (year, last_seq) VALUES (?, 0)", [year], (err) => {
                if (err) return db.run("ROLLBACK", () => reject(err));

                db.run("UPDATE doc_sequences SET last_seq = last_seq + 1 WHERE year = ?", [year], (err) => {
                    if (err) return db.run("ROLLBACK", () => reject(err));

                    db.get("SELECT last_seq FROM doc_sequences WHERE year = ?", [year], (err, row) => {
                        if (err || !row) return db.run("ROLLBACK", () => reject(err || new Error("채번 실패")));

                        db.run("COMMIT", (err) => {
                            if (err) return db.run("ROLLBACK", () => reject(err));
                            resolve(`사무국-${year}-${String(row.last_seq).padStart(4, '0')}`);
                        });
                    });
                });
            });
        });
    });
}

function getSiteUrl() {
    return new Promise((resolve) => {
        db.get("SELECT value FROM settings WHERE key = 'site_url'", [], (e, row) => {
            let url = (row && row.value) ? row.value.trim() : 'http://localhost:8081';
            if (url.endsWith('/')) url = url.slice(0, -1);
            resolve(url);
        });
    });
}

function clearStaleLocks() {
    // [수정] lock acquire/form 체크와 동일한 3분 기준으로 통일
    const timeout = new Date(Date.now() - 3 * 60 * 1000).toISOString();
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
                db.run(`ALTER TABLE expenditures ADD COLUMN ${col.name} ${col.type}`, (err) => {
                    if (err && !/duplicate column name/i.test(err.message)) {
                        console.error(`[DB Migrate Runtime] expenditures.${col.name} 추가 실패:`, err.message);
                    }
                });
                added++;
            }
        });

        // [컬럼 통합 마이그레이션]
        // presDate, presidentSignedDate -> executionDate 로 통합.
        // 데이터 복사 후 두 컬럼을 DROP 한다.
        // secPhone, presPhone 은 코드 어디에서도 읽거나 쓰지 않아 함께 제거한다.
        // ALTER TABLE ... DROP COLUMN 은 SQLite 3.35.0+ 에서 지원된다.
        const dropTargets = [
            {
                col: 'presDate',
                before: () => new Promise((resolve) => {
                    db.run(
                        // presDate가 있는 행(= 총동문회장이 결재한 문서)은
                        // executionDate 기존값(기안일)과 무관하게 결재일로 덮어쓴다.
                        `UPDATE expenditures SET executionDate = presDate
                         WHERE presDate IS NOT NULL AND presDate != ''`,
                        (e) => {
                            if (!e) console.log(">> [DB Migrate] presDate -> executionDate 복사 완료.");
                            resolve();
                        }
                    );
                }),
            },
            { col: 'presidentSignedDate', before: null },
            { col: 'secPhone',  before: null },
            { col: 'presPhone', before: null },
        ];

        (async () => {
            for (const target of dropTargets) {
                if (!existingNames.includes(target.col)) continue;
                if (target.before) await target.before();
                db.run(`ALTER TABLE expenditures DROP COLUMN ${target.col}`, (e) => {
                    if (!e) {
                        console.log(`>> [DB Migrate] 컬럼 삭제 완료: ${target.col}`);
                    } else {
                        console.warn(`>> [DB Migrate] 컬럼 삭제 실패(SQLite 3.35+ 필요): ${target.col} -`, e.message);
                    }
                });
            }
        })();

        console.log(`>> [DB Check] 검사 완료. (추가된 컬럼: ${added}개)`);
    });
}

module.exports = { getTodayKST, getUser, getUserByPos, getNextDocNum, getSiteUrl, clearStaleLocks, logAction, checkAndMigrateDB };