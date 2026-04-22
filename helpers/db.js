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

// [A-1] .env의 SMTP_* 값을 DB settings 로 1회 이관
// DB의 smtp_host가 비어있고 .env에 SMTP_HOST가 있을 때만 동작
// 이미 관리자가 DB에서 설정을 바꾼 뒤라면 절대 덮어쓰지 않음
function migrateEnvMailToDB() {
    db.get("SELECT value FROM settings WHERE key = 'smtp_host'", [], (err, row) => {
        if (err) {
            console.error('[DB Migrate] smtp_host 조회 실패:', err.message);
            return;
        }
        const dbHostEmpty = !row || !row.value;
        const envHost = process.env.SMTP_HOST;
        if (!dbHostEmpty || !envHost) return;

        const envMap = {
            smtp_host: process.env.SMTP_HOST || '',
            smtp_port: process.env.SMTP_PORT || '465',
            smtp_user: process.env.SMTP_USER || '',
            smtp_pass: process.env.SMTP_PASS || ''
        };
        const stmt = db.prepare("UPDATE settings SET value = ? WHERE key = ?");
        Object.entries(envMap).forEach(([k, v]) => {
            stmt.run([v, k], (e) => {
                if (e) console.error(`[DB Migrate] .env → DB 이관 실패(${k}):`, e.message);
            });
        });
        stmt.finalize(() => {
            console.log('>> [DB Migrate] .env의 SMTP 설정을 DB로 1회 이관했습니다. 이후에는 관리자 화면에서 관리됩니다.');
        });
    });
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

        // [A-1] .env → DB 1회 이관 시도
        migrateEnvMailToDB();

        console.log(`>> [DB Check] 검사 완료. (추가된 컬럼: ${added}개)`);
    });
}

// [A-1] settings 키 배열을 한 번에 조회하여 {key: value} 객체로 반환.
// 누락된 key는 빈 문자열로 채워준다.
function getSettings(keys) {
    return new Promise((resolve, reject) => {
        if (!Array.isArray(keys) || keys.length === 0) return resolve({});
        const placeholders = keys.map(() => '?').join(',');
        db.all(
            `SELECT key, value FROM settings WHERE key IN (${placeholders})`,
            keys,
            (err, rows) => {
                if (err) return reject(err);
                const result = {};
                keys.forEach(k => { result[k] = ''; });
                (rows || []).forEach(r => { result[r.key] = r.value == null ? '' : String(r.value); });
                resolve(result);
            }
        );
    });
}

// [A-1] settings 일괄 upsert. undefined 값은 스킵(미변경), 빈 문자열은 저장.
// 원자성 보장을 위해 BEGIN IMMEDIATE 트랜잭션 사용.
function saveSettings(obj) {
    return new Promise((resolve, reject) => {
        if (!obj || typeof obj !== 'object') return resolve();
        const entries = Object.entries(obj).filter(([, v]) => v !== undefined);
        if (entries.length === 0) return resolve();

        db.serialize(() => {
            db.run('BEGIN IMMEDIATE', (e) => {
                if (e) return reject(e);
                const stmt = db.prepare(
                    'INSERT INTO settings (key, value) VALUES (?, ?) ' +
                    'ON CONFLICT(key) DO UPDATE SET value = excluded.value'
                );
                let pending = entries.length;
                let failed = false;
                entries.forEach(([k, v]) => {
                    stmt.run([k, v == null ? '' : String(v)], (err) => {
                        if (failed) return;
                        if (err) {
                            failed = true;
                            db.run('ROLLBACK', () => reject(err));
                            return;
                        }
                        pending -= 1;
                        if (pending === 0) {
                            stmt.finalize((ferr) => {
                                if (ferr) return db.run('ROLLBACK', () => reject(ferr));
                                db.run('COMMIT', (cerr) => cerr ? reject(cerr) : resolve());
                            });
                        }
                    });
                });
            });
        });
    });
}

module.exports = {
    getTodayKST, getUser, getUserByPos, getNextDocNum, getSiteUrl,
    clearStaleLocks, logAction, checkAndMigrateDB,
    getSettings, saveSettings
};