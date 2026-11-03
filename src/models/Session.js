const mongoose = require('mongoose');

// sessions / devices
const sessionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  deviceId: { type: String },
  deviceName: { type: String },
  userAgent: { type: String },
  ip: { type: String },
  lastActiveAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
  revokedAt: { type: Date },
  revokedReason: { type: String },
  createdAt: { type: Date, default: Date.now },
});

sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('Session', sessionSchema);