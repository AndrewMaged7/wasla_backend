const mongoose = require('mongoose');
const env = require('./env');
const { User, Otp, Session, SecurityEvent } = require('../models');
const { promoteAdminPhones } = require('./admin');

async function connectDatabase() {
  await mongoose.connect(env.MONGO_URI);
  console.log('Connected to MongoDB');

  try {
    // codes from the old version (before "phone" became "target") so the new index does not conflict
    await Otp.deleteMany({ target: { $exists: false } });
    // sync indexes (drops outdated ones)
    await User.syncIndexes();
    await Otp.syncIndexes();
    await Session.syncIndexes();
    await SecurityEvent.syncIndexes();

    await promoteAdminPhones();
  } catch (setupErr) {
    console.error('WARN: database setup problem:', setupErr.message);
  }
}

module.exports = { connectDatabase };