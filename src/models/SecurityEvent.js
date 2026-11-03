const mongoose = require('mongoose');

// security event log
const securityEventSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, required: true },
  ip: { type: String },
  userAgent: { type: String },
  meta: { type: mongoose.Schema.Types.Mixed },
  createdAt: { type: Date, default: Date.now },
});

securityEventSchema.index({ createdAt: 1 }, { expireAfterSeconds: 180 * 24 * 60 * 60 }); // deleted after 180 days

module.exports = mongoose.model('SecurityEvent', securityEventSchema);