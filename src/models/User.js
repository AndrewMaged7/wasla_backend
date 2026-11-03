const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: [true, 'Name is required'], trim: true, minlength: 2, maxlength: 50 },
    phone: { type: String, required: [true, 'Phone number is required'], trim: true },
    email: { type: String, lowercase: true, trim: true }, // only set after it has been verified
    password: { type: String, required: true, select: false },
    isPhoneVerified: { type: Boolean, default: false },

    // rider = passenger, driver = driver, admin = staff
    role: { type: String, enum: ['rider', 'driver', 'admin'], default: 'rider' },

    // profile data
    photo: { type: String }, // file name only
    gender: { type: String, enum: ['male', 'female'] },
    dateOfBirth: { type: Date },

    // account settings
    settings: {
      language: { type: String, enum: ['ar', 'en'], default: 'ar' },
      notifications: {
        push: { type: Boolean, default: true },
        sms: { type: Boolean, default: true },
        email: { type: Boolean, default: true },
        promotions: { type: Boolean, default: false },
      },
    },

    // pending phone / email changes (waiting for the verification code)
    pendingPhone: { type: String },
    pendingEmail: { type: String },

    // acceptance of the terms and privacy policy (time + version)
    termsAcceptedAt: { type: Date, required: true },
    termsVersion: { type: String, required: true },
    privacyAcceptedAt: { type: Date, required: true },
    privacyVersion: { type: String, required: true },

    // account status: active / temporarily suspended / banned / deleted
    status: { type: String, enum: ['active', 'suspended', 'banned', 'deleted'], default: 'active' },
    statusReason: { type: String }, // internal reason for staff only, never returned to the user
    statusChangedAt: { type: Date },
    suspendedUntil: { type: Date },

    // suspicious activity / abuse
    flagged: { type: Boolean, default: false },
    flagReason: { type: String },
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
    lastLoginAt: { type: Date },

    // identity verification (KYC)
    identity: {
      status: { type: String, enum: ['none', 'pending', 'approved', 'rejected'], default: 'none' },
      submittedAt: { type: Date },
      reviewedAt: { type: Date },
      reviewedBy: { type: mongoose.Schema.Types.ObjectId },
      rejectionReason: { type: String },
      docs: { front: String, back: String, selfie: String },
    },
  },
  { timestamps: true }
);

// unique phone and email (documents without a value are ignored)
userSchema.index({ phone: 1 }, { unique: true, partialFilterExpression: { phone: { $type: 'string' } } });
userSchema.index({ email: 1 }, { unique: true, partialFilterExpression: { email: { $type: 'string' } } });
userSchema.index({ status: 1 });
userSchema.index({ flagged: 1 });
userSchema.index({ 'identity.status': 1 });

// updates a user and returns the fresh document: User.updateAndGet(id, { $set: { ... } })
userSchema.statics.updateAndGet = async function updateAndGet(id, update) {
  await this.updateOne({ _id: id }, update);
  return this.findById(id);
};

module.exports = mongoose.model('User', userSchema);