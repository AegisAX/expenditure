const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs'); 
const crypto = require('crypto'); // [추가] 랜덤 문자열 생성을 위한 모듈
const db = new sqlite3.Database('./db/data.sqlite');

db.serialize(() => {
  // [성능] WAL 모드 + 동기 모드 완화로 동시성·쓰기 성능 개선
  // NORMAL은 크래시 시 마지막 트랜잭션 일부 손실 가능성이 있으나 SQLite 자체 무결성은 유지
  // 서버 무중단 운영 환경에서 허용 가능한 트레이드오프
  db.run("PRAGMA journal_mode = WAL");
  db.run("PRAGMA synchronous = NORMAL");
  db.run("PRAGMA foreign_keys = ON");

  // 1. Users 테이블
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    name TEXT,
    position TEXT,
    phone TEXT,
    signature_path TEXT,
    status TEXT DEFAULT 'Pending',
    generation INTEGER,
    role TEXT DEFAULT 'User', 
    login_fail_count INTEGER DEFAULT 0,
    locked_until DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // [버전 호환성] 기존 DB에 컬럼이 없는 경우를 대비한 마이그레이션, 이미 컬럼이 있는 경우(duplicate) 외의 오류는 로그 출력
  db.run("ALTER TABLE users ADD COLUMN login_fail_count INTEGER DEFAULT 0", (err) => {
    if (err && !/duplicate column name/i.test(err.message)) {
      console.error('[DB Migrate] users.login_fail_count 추가 실패:', err.message);
    }
  });
  db.run("ALTER TABLE users ADD COLUMN locked_until DATETIME", (err) => {
    if (err && !/duplicate column name/i.test(err.message)) {
      console.error('[DB Migrate] users.locked_until 추가 실패:', err.message);
    }
  });

  // 2. Settings 테이블
  db.run(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);

  // 3. Expenditures 테이블
  db.run(`CREATE TABLE IF NOT EXISTS expenditures (
    docNum TEXT PRIMARY KEY,
    applicantEmail TEXT,
    subject TEXT,
    bodyContent TEXT,
    totalAmount INTEGER,
    executionDate TEXT,
    reqDate TEXT,
    payDate TEXT,
    items JSON,
    status TEXT,
    appPos TEXT, appName TEXT, appPhone TEXT, appSig TEXT,
    secName TEXT, secSig TEXT, secDate TEXT,
    presName TEXT, presSig TEXT,
    file_paths TEXT,
    
    locked_by_name TEXT,
    locked_by_email TEXT,
    locked_at DATETIME,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // [버전 호환성] 기존 DB 마이그레이션
  const lockColumns = [
    { name: 'locked_by_name',  type: 'TEXT' },
    { name: 'locked_by_email', type: 'TEXT' },
    { name: 'locked_at',       type: 'DATETIME' }
  ];
  lockColumns.forEach(col => {
    db.run(`ALTER TABLE expenditures ADD COLUMN ${col.name} ${col.type}`, (err) => {
      if (err && !/duplicate column name/i.test(err.message)) {
        console.error(`[DB Migrate] expenditures.${col.name} 추가 실패:`, err.message);
      }
    });
  });
  
  // [추가] 문서 번호 채번을 위한 시퀀스 테이블
  db.run(`CREATE TABLE IF NOT EXISTS doc_sequences (
    year INTEGER PRIMARY KEY,
    last_seq INTEGER DEFAULT 0
  )`);
  
  // 4. Audit Logs 테이블 생성
  db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT,
    user_name TEXT,
    action TEXT,          /* 작업 종류: Login, Logout, Delete, Update 등 */
    details TEXT,         /* 상세 내용 (JSON 또는 문자열) */
    ip_address TEXT,      /* 접속 IP */
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // 기본 정보 설정
  const defaultSettings = [
    { key: 'address', value: '(04210) 서울특별시 마포구 마포대로14길 14(공덕동), 태영빌딩 6층 (제20대 금오공업고등학교 총동문회)' },
    { key: 'admin_phone', value: '02-3275-0118' }
  ];
  defaultSettings.forEach(setting => {
    db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`, [setting.key, setting.value]);
  });

  // ============================================================
  // [보안 패치] 관리자 계정 초기 생성 로직 개선 (1.1 하드코딩 제거)
  // ============================================================
  const adminEmail = 'admin@whitehat.kr';
  const adminName = '시스템 관리자';

  db.get("SELECT id FROM users WHERE email = ?", [adminEmail], (err, row) => {
    if (!row) {
        // 1. 랜덤 비밀번호 생성 (16자리 Hex 문자열)
        const randomPw = crypto.randomBytes(8).toString('hex');
        
        // 2. 비밀번호 해싱
        const hash = bcrypt.hashSync(randomPw, 10);

        db.run(`INSERT INTO users (email, password, name, position, phone, role, status, generation) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [adminEmail, hash, adminName, 'System Admin', '010-0000-0000', 'Admin', 'Approved', 0],
                (err) => {
                    if (!err) {
                        // 3. 로그에 초기 비밀번호 출력 (관리자 확인용)
                        console.log('\n================================================================');
                        console.log('🚨 [Security Notice] 관리자 계정이 초기 생성되었습니다.');
                        console.log(`👉 ID : ${adminEmail}`);
                        console.log(`👉 PW : ${randomPw}`); // 무작위 생성된 비밀번호 출력
                        console.log('⚠️  보안을 위해 최초 로그인 후 [정보 수정]에서 반드시 비밀번호를 변경하세요.');
                        console.log('================================================================\n');
                    } else {
                        console.error('[System Error] 관리자 계정 생성 실패:', err);
                    }
                }
        );
    }
  });
});

module.exports = db;