const nodemailer = require('nodemailer');
const { getSettings } = require('./db');

// 현재 활성 transporter (DB 설정 미충족 시 null)
let transporter = null;

// 마지막으로 로드한 설정 (테스트 메일 발송, 디버깅용)
let currentMailSettings = {
    smtp_host: '',
    smtp_port: '',
    smtp_user: '',
    smtp_pass: '',
    mail_from_name: ''
};

// SMTP 호스트가 IP 주소(IPv4/IPv6)인지 판별.
// IP 일 경우 TLS 인증서 검증 우회 (자체 서명/사내망 자체 SMTP 서버 대응).
function isIpAddress(host) {
    if (!host) return false;
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6 = /:/;
    return ipv4.test(host) || ipv6.test(host);
}

const MAIL_KEYS = ['smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'mail_from_name'];

/**
 * DB에서 메일 설정을 읽어 transporter를 (재)생성한다.
 * 서버 기동 시 1회, 관리자 설정 저장 후 매번 호출된다.
 * 필수값(host/user/pass)이 하나라도 없으면 transporter는 null 로 설정되며
 * sendEmail() 은 no-op 이 된다 (기존 동작과 동일).
 */
async function initTransporter() {
    try {
        const s = await getSettings(MAIL_KEYS);
        currentMailSettings = s;

        // 기존 transporter가 있으면 안전하게 닫기
        if (transporter && typeof transporter.close === 'function') {
            try { transporter.close(); } catch (_) { /* ignore */ }
        }

        if (!s.smtp_host || !s.smtp_user || !s.smtp_pass) {
            transporter = null;
            console.warn('[Mail Warning] SMTP 설정이 비어 있어 메일 기능이 비활성화됩니다. 관리자 화면에서 설정하세요.');
            return;
        }

        const port = parseInt(s.smtp_port, 10) || 465;
        const transportConfig = {
            host: s.smtp_host,
            port,
            secure: port === 465,
            auth: { user: s.smtp_user, pass: s.smtp_pass },
            pool: true,
            maxConnections: 1,
            rateLimit: 3,
            connectionTimeout: 10000
        };
        // [개선] SMTP 호스트가 IP 주소면 TLS 인증서 검증 우회.
        // 사내망 자체 서버 + 도메인 미발급 환경 대응. 인터넷 SMTP에는 도메인 사용 권장.
        if (isIpAddress(s.smtp_host)) {
            transportConfig.tls = { rejectUnauthorized: false };
            console.warn('>> [Mail] SMTP 호스트가 IP 주소 - TLS 인증서 검증 우회 (보안 약화 주의).');
        }
        transporter = nodemailer.createTransport(transportConfig);
        console.log(`>> [Mail] Transporter 초기화 완료 (host=${s.smtp_host}, port=${port}, user=${s.smtp_user}).`);
    } catch (e) {
        transporter = null;
        console.error('[Mail Error] Transporter 초기화 실패:', e.message);
    }
}

/**
 * 관리자 설정 저장 직후 호출. DB에서 새 값을 다시 읽어 transporter를 재생성.
 */
async function reloadTransporter() {
    await initTransporter();
}

/**
 * 현재 메모리에 로드된 설정 반환 (마스킹 없음 — 내부용).
 * 관리자 화면 노출용 마스킹은 routes/admin.js 에서 수행.
 */
function getCurrentMailSettings() {
    return { ...currentMailSettings };
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function makeEmailHtml(docNum, subject, applicantName, statusMsg, siteUrl) {
    const safeDoc = escapeHtml(docNum);
    const safeSubject = escapeHtml(subject);
    const safeName = escapeHtml(applicantName);
    const safeStatus = escapeHtml(statusMsg);
    const link = `${siteUrl}/login?docNum=${encodeURIComponent(docNum)}`;
    return `
<div style="font-family:'Malgun Gothic','맑은 고딕',sans-serif;max-width:520px;margin:0 auto;padding:20px;border:1px solid #e0e0e0;border-radius:8px;">
    <h2 style="color:#2c3e50;border-bottom:2px solid #2c3e50;padding-bottom:8px;">금오공고 총동문회 전자결재</h2>
    <p style="font-size:15px;color:#333;">${safeStatus}</p>
    <table style="width:100%;font-size:14px;color:#444;margin:16px 0;">
        <tr><td style="padding:6px 0;width:110px;color:#888;">문서번호</td><td>${safeDoc}</td></tr>
        <tr><td style="padding:6px 0;color:#888;">제목</td><td>${safeSubject}</td></tr>
        <tr><td style="padding:6px 0;color:#888;">신청자</td><td>${safeName}</td></tr>
    </table>
    <p style="margin-top:20px;">
        <a href="${link}" style="display:inline-block;padding:10px 18px;background:#2c3e50;color:#fff;text-decoration:none;border-radius:4px;font-size:14px;">문서 확인</a>
    </p>
    <p style="margin-top:24px;font-size:12px;color:#999;">본 메일은 전자결재 시스템에서 자동 발송되었습니다.</p>
</div>`;
}

/**
 * 메일 발송. 시그니처는 기존과 동일.
 * transporter가 null 이면 조용히 무시 (비즈니스 로직 차단 방지).
 */
function sendEmail(to, subject, html) {
    if (!transporter) {
        console.warn('[Mail Skip] transporter 미설정 - 발송 생략:', { to, subject });
        return Promise.resolve({ success: false, error: 'SMTP 설정이 비어 있어 메일 기능이 비활성화 상태입니다.' });
    }
    if (!to) {
        console.warn('[Mail Skip] 수신자 누락 - 발송 생략:', { subject });
        return Promise.resolve({ success: false, error: '수신자가 지정되지 않았습니다.' });
    }

    const fromName = currentMailSettings.mail_from_name || '금오공고 총동문회 사무국';
    const fromAddr = currentMailSettings.smtp_user;
    const from = `"${fromName}" <${fromAddr}>`;

    console.log('[Mail Send] 요청:', { to, subject });

    return new Promise((resolve) => {
        transporter.sendMail({ from, to, subject, html }, (err, info) => {
            if (err) {
                console.error('[Mail Error]', { to, subject, error: err.message });
                return resolve({ success: false, error: err.message });
            }
            console.log('[Mail Sent]', {
                to,
                subject,
                messageId: info.messageId,
                response: info.response
            });
            resolve({ success: true });
        });
    });
}

module.exports = {
    initTransporter,
    reloadTransporter,
    getCurrentMailSettings,
    sendEmail,
    escapeHtml,
    makeEmailHtml
};