const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const argon2   = require('argon2');

const UserSchema = new mongoose.Schema({
  name:         { type: String, required: true, trim: true },
  email:        { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:     { type: String, required: true },
  phone:        { type: String, default: '' },

  role: {
    type:    String,
    enum:    [
      'superadmin', 'partner_admin', 'company_admin', 'department_admin', 'analyst',
      'soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst',
    ],
    default: 'analyst',
  },

  tenantId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Company',    default: null },
  socManagerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  socManagerPool: { type: Boolean, default: false, index: true },
  superadminManaged: { type: Boolean, default: false, index: true },
  // Primary department (backwards compat)
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null },
  // Multi-department access (analyst can be in multiple depts of same company)
  departmentIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Department' }],

  isActive:   { type: Boolean, default: true },
  accountStatus: {
    type: String,
    enum: ['invited', 'active', 'disabled', 'suspended', 'expired'],
    default: 'active',
    index: true,
  },
  isEmailVerified: { type: Boolean, default: false },
  forcePasswordReset: { type: Boolean, default: false },
  maxWorkload: { type: Number, min: 1, max: 1000, default: 10 },
  passwordChangedAt: { type: Date, default: null },
  mfaEnabled: { type: Boolean, default: false },
  lastLogin:  { type: Date },
  
  // OTP verification fields
  otp:        { type: String, default: null },
  otpExpires: { type: Date, default: null },
  otpAttempts: { type: Number, default: 0 },

  // 2FA / Google Authenticator (TOTP)
  twoFactorSecret:  { type: String, default: null, select: false }, // legacy; migrated to encrypted form on use
  twoFactorSecretEncrypted: { type: mongoose.Schema.Types.Mixed, default: null, select: false },
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorPending: { type: Boolean, default: false },  // setup in-progress
}, { timestamps: true });

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await argon2.hash(this.password, {
    type: argon2.argon2id,
    memoryCost: Number(process.env.ARGON2_MEMORY_KIB || 65536),
    timeCost: Number(process.env.ARGON2_TIME_COST || 3),
    parallelism: Number(process.env.ARGON2_PARALLELISM || 1),
    hashLength: 32,
  });
  next();
});

UserSchema.methods.comparePassword = async function (plain) {
  const encoded = String(this.password || '');
  if (encoded.startsWith('$argon2id$')) return argon2.verify(encoded, plain);
  // Rolling migration: a successful legacy bcrypt login is upgraded in place.
  const valid = await bcrypt.compare(plain, encoded);
  if (valid) {
    this.password = plain;
    await this.save();
  }
  return valid;
};

UserSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  delete obj.twoFactorSecret;
  delete obj.twoFactorSecretEncrypted;
  delete obj.otp;
  delete obj.otpExpires;
  delete obj.otpAttempts;
  return obj;
};

module.exports = mongoose.model('User', UserSchema);
