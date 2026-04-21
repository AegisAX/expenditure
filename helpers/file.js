const path = require('path');
const fs = require('fs');
const multer = require('multer');

const uploadDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;  // 25MB — 클라/서버/문서 공통
const MAX_UPLOAD_MB    = 25;

const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            let targetDir = uploadDir;
            if (file.fieldname === 'signatureFile') {
                targetDir = path.join(uploadDir, 'signatures');
            } else if (file.fieldname === 'newAttachments') {
                const d = new Date();
                const year = d.getFullYear().toString();
                const month = String(d.getMonth() + 1).padStart(2, '0');
                targetDir = path.join(uploadDir, 'evidence', year, month);
            }
            fs.mkdirSync(targetDir, { recursive: true });
            cb(null, targetDir);
        },
        filename: (req, file, cb) => {
            const tempName = `temp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            cb(null, tempName);
        }
    }),
    limits: { fileSize: MAX_UPLOAD_BYTES }
});

async function saveFile(base64Data, type, prefix) {
    if (!base64Data) return '';
    try {
        let ext = '.jpg';
        if (type && type.includes('image/png')) ext = '.png';
        const sigDir = path.join(uploadDir, 'signatures');
        await fs.promises.mkdir(sigDir, { recursive: true });
        const filename = `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}${ext}`;
        const filePath = path.join(sigDir, filename);
        await fs.promises.writeFile(filePath, Buffer.from(base64Data, 'base64'), { mode: 0o644 });
        return path.join('signatures', filename).replace(/\\/g, '/');
    } catch (e) {
        console.error('File Save Error:', e);
        return '';
    }
}

module.exports = { uploadDir, upload, saveFile, MAX_UPLOAD_BYTES, MAX_UPLOAD_MB };