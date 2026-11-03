const mongoose = require('mongoose');

// verification codes (target = phone number or email)
const otpSchema = new mongoose.Schema({
  target: { type: String, required: true },
  purpose: { type: String, required: true }, // signup | reset | change_phone:<userId> | change_email:<userId>
  codeHash: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  attempts: { type: Number, default: 0 },
  lastSentAt: { type: Date, required: true },
});

otpSchema.index({ target: 1, purpose: 1 }, { unique: true });
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // auto-delete after expiry

module.exports = mongoose.model('Otp', otpSchema);