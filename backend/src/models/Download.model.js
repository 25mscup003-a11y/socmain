const mongoose = require('mongoose');

const DownloadSchema = new mongoose.Schema({
  companyId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  systemId:   { type: mongoose.Schema.Types.ObjectId, ref: 'System',  sparse: true, index: true },
  downloadType: { 
    type:    String,
    enum:    [
      'bundle', 'deb', 'rpm', 'exe', 'msi', 'pkg', 'macpkg', 'dmg', 'zip', 'apk', 'solaris',
      'update-deb', 'update-rpm', 'update-exe', 'update-msi', 'update-pkg',
      'update-macpkg', 'update-dmg', 'update-apk', 'update-solaris',
    ],
    default: 'bundle',
  },
  downloadCategory: {
    type: String,
    enum: ['system', 'server', 'android', 'universal'],
    default: 'system',
    index: true,
  },
  fileName:     { type: String },
  artifactSha256: { type: String, match: /^[a-f0-9]{64}$/i },
  ipAddress:    { type: String },
  userAgent:    { type: String },
  userId:       { type: mongoose.Schema.Types.ObjectId, ref: 'User', sparse: true },
  createdAt:    { type: Date, default: Date.now, index: true },
  expiresAt:    { type: Date }, // When this download counts toward the limit (optional cleanup)
}, { timestamps: false });

// Index to quickly count downloads per company
DownloadSchema.index({ companyId: 1, createdAt: -1 });

// Auto-remove old downloads if expiresAt is set (optional)
DownloadSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0, sparse: true });

module.exports = mongoose.model('Download', DownloadSchema);
