const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || '',
    port: parseInt(process.env.SMTP_PORT) || 465,
    secure: true,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    pool: true, maxConnections: 1, rateLimit: 3, timeout: 10000
});

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function makeEmailHtml(docNum, subject, applicant, statusMsg, baseUrl) {
    return `<div style="padding:20px;border:1px solid #ddd;">
        <h2>${escapeHtml(statusMsg)}</h2>
        <p>문서번호: ${escapeHtml(docNum)}</p>
        <p>제목: ${escapeHtml(subject)}</p>
        <p>기안자: ${escapeHtml(applicant)}</p>
        <hr>
        <a href="${escapeHtml(baseUrl)}/login?docNum=${encodeURIComponent(docNum || '')}">문서 확인</a>
    </div>`;
}

async function sendEmail(to, sub, html) {
    if (!to) return;
    try {
        await transporter.sendMail({ from: process.env.SMTP_USER, to, subject: sub, html });
    } catch (e) {
        console.error('[Mail Error]', e);
    }
}

module.exports = { escapeHtml, makeEmailHtml, sendEmail };