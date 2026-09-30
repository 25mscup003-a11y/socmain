const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ── Ensure upload directories exist ────────────────────
const UPLOAD_ROOT = path.join(__dirname, '../../uploads');
const AGREEMENT_DIR = path.join(UPLOAD_ROOT, 'agreements');
const PARTNER_DOCS_DIR = path.join(UPLOAD_ROOT, 'partner-docs');
const PARTNER_AVATARS_DIR = path.join(UPLOAD_ROOT, 'partner-avatars');

[UPLOAD_ROOT, AGREEMENT_DIR, PARTNER_DOCS_DIR, PARTNER_AVATARS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ── Agreement PDF storage ───────────────────────────────
const agreementStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, AGREEMENT_DIR),
  filename: (req, file, cb) => {
    const partnerId = req.params.id || 'unknown';
    const ext = path.extname(file.originalname).toLowerCase() || '.pdf';
    const timestamp = Date.now();
    cb(null, `agreement-${partnerId}-${timestamp}${ext}`);
  },
});

const pdfFilter = (_req, file, cb) => {
  if (file.mimetype === 'application/pdf') return cb(null, true);
  cb(new Error('Only PDF files are allowed for agreement upload'), false);
};

const agreementUpload = multer({
  storage: agreementStorage,
  fileFilter: pdfFilter,
  limits: { fileSize: 8 * 1024 * 1024 }, // 8 MB
});

// ── Partner KYC Documents (PDF/image) ──────────────────
const partnerDocStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, PARTNER_DOCS_DIR),
  filename: (req, file, cb) => {
    const partnerId = req.user?.partnerId || 'unknown';
    const docType = String(req.body?.docType || 'document').replace(/[^a-zA-Z0-9_-]/g, '');
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `doc-${partnerId}-${docType}-${Date.now()}${ext}`);
  },
});

const docFilter = (req, file, cb) => {
  const allowed = ['application/pdf', 'image/png', 'image/jpeg'];
  const docTypes = ['gstCertificate', 'panCard', 'businessRegistration'];
  if (!docTypes.includes(req.body?.docType)) return cb(new Error('Invalid KYC document type'), false);
  if (allowed.includes(file.mimetype)) return cb(null, true);
  cb(new Error('Only PDF, PNG, or JPG files are allowed'), false);
};

const partnerDocUpload = multer({
  storage: partnerDocStorage,
  fileFilter: docFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
});

// ── Partner Avatar (image only) ─────────────────────────
const partnerAvatarStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, PARTNER_AVATARS_DIR),
  filename: (req, file, cb) => {
    const partnerId = req.user?.partnerId || 'unknown';
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `avatar-${partnerId}-${Date.now()}${ext}`);
  },
});

const imageFilter = (_req, file, cb) => {
  if (['image/png', 'image/jpeg'].includes(file.mimetype)) return cb(null, true);
  cb(new Error('Only PNG or JPG images are allowed'), false);
};

const partnerAvatarUpload = multer({
  storage: partnerAvatarStorage,
  fileFilter: imageFilter,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2 MB
});

module.exports = { agreementUpload, partnerDocUpload, partnerAvatarUpload, UPLOAD_ROOT };
