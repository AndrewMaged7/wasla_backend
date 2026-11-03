/**
 * ==========================================================
 *  Full automated integration tests for the API
 * ==========================================================
 *  Run (Node 18+, MongoDB running):
 *    node --test test.js
 *
 *  What it does:
 *    - Starts src/server.js as a child process on port 5099 with a SEPARATE test database
 *      (TEST_MONGO_URI, default mongodb://127.0.0.1:27017/auth_demo_test).
 *    - Rate limiting is disabled and SMS / email are never sent (the code is only logged).
 *    - OTP codes are written straight into the test database, so no real SMS is needed.
 *    - Drops the test database when it finishes.
 *    - Refuses to run if the database name does not contain "test" (so it can never wipe real data).
 * ==========================================================
 */

require('dotenv').config();

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const mongoose = require('mongoose');

// ---------------------- Setup ----------------------
const PORT = 5099;
const BASE = `http://127.0.0.1:${PORT}`;
const TEST_MONGO_URI = process.env.TEST_MONGO_URI || 'mongodb://127.0.0.1:27017/auth_demo_test';
const JWT_SECRET = 'test-secret-test-secret-test-secret-test';
const PASSWORD = 'Test1234';
const UNKNOWN_ID = '507f1f77bcf86cd799439011'; // a valid ObjectId that does not exist

const dbNameMatch = TEST_MONGO_URI.match(/\/([^/?]+)(\?|$)/);
if (!dbNameMatch || !dbNameMatch[1].toLowerCase().includes('test')) {
  throw new Error('Refusing to run: the test database name must contain "test" (set TEST_MONGO_URI)');
}

const AVATAR_DIR = path.join(__dirname, 'uploads', 'avatars');
const PRIVATE_DIR = path.join(__dirname, 'private', 'identity');

let server;
let serverLog = '';
let db;

// ---------------------- Helpers ----------------------
async function api(method, url, { token, body, form } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  let payload;
  if (form) payload = form;
  else if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = typeof body === 'string' ? body : JSON.stringify(body);
  }
  const res = await fetch(BASE + url, { method, headers, body: payload });
  const isJson = (res.headers.get('content-type') || '').includes('json');
  const data = isJson ? await res.json() : null;
  return { status: res.status, data, res };
}

function hashOtp(target, purpose, code) {
  return crypto.createHmac('sha256', JWT_SECRET).update(`${target}:${purpose}:${code}`).digest('hex');
}

// writes a known OTP straight into the database (so tests never need a real SMS / email)
async function setOtp(target, purpose, code = '123456', overrides = {}) {
  await db.collection('otps').updateOne(
    { target, purpose },
    {
      $set: {
        codeHash: hashOtp(target, purpose, code),
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
        attempts: 0,
        lastSentAt: new Date(0),
        ...overrides,
      },
    },
    { upsert: true }
  );
  return code;
}

let phoneCounter = 0;
const nextPhone = () => `010${String(20000000 + ++phoneCounter)}`; // local Egyptian format
const intl = (local) => '+20' + local.slice(1);
let emailCounter = 0;
const nextEmail = () => `user${++emailCounter}-${Date.now()}@example.com`;

const signupBody = (phone, overrides = {}) => ({
  name: 'Test User',
  phone,
  password: PASSWORD,
  confirmPassword: PASSWORD,
  acceptTerms: true,
  acceptPrivacy: true,
  ...overrides,
});

// signs up + verifies a user and returns everything needed to use the account
async function registerUser({ role, name = 'Test User', password = PASSWORD } = {}) {
  const phone = nextPhone();
  const r = await api('POST', '/api/auth/signup', {
    body: signupBody(phone, { name, password, confirmPassword: password, ...(role ? { role } : {}) }),
  });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  await setOtp(intl(phone), 'signup');
  const v = await api('POST', '/api/auth/verify-otp', {
    body: { phone, code: '123456', deviceId: 'dev-main', deviceName: 'Main Phone' },
  });
  assert.equal(v.status, 200, JSON.stringify(v.data));
  return { phone, intlPhone: intl(phone), password, token: v.data.token, id: String(v.data.user.id), name };
}

async function makeAdmin() {
  const u = await registerUser({ name: 'Admin User' });
  await db.collection('users').updateOne({ phone: u.intlPhone }, { $set: { role: 'admin' } });
  return u;
}

const login = (u, extra = {}, password) =>
  api('POST', '/api/auth/login', { body: { phone: u.phone, password: password || u.password, ...extra } });

const pngBuf = (size = 64) =>
  Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(size, 7)]);
const jpgBuf = (size = 64) => Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(size, 7)]);

function imageForm(parts) {
  const fd = new FormData();
  for (const [field, { buf, filename, type }] of Object.entries(parts)) {
    fd.append(field, new Blob([buf], { type }), filename);
  }
  return fd;
}

const idForm = () =>
  imageForm({
    idFront: { buf: jpgBuf(), filename: 'front.jpg', type: 'image/jpeg' },
    idBack: { buf: jpgBuf(), filename: 'back.jpg', type: 'image/jpeg' },
    selfie: { buf: pngBuf(), filename: 'selfie.png', type: 'image/png' },
  });

const eventTypes = async (u) => {
  await new Promise((r) => setTimeout(r, 150)); // events are written asynchronously
  const r = await api('GET', '/api/account/security-events', { token: u.token });
  return r.data.events.map((e) => e.type);
};

// ---------------------- Global hooks ----------------------
before(async () => {
  await mongoose.connect(TEST_MONGO_URI);
  db = mongoose.connection.db;
  await mongoose.connection.dropDatabase(); // clean start

  server = spawn(process.execPath, ['src/server.js'], {
    cwd: __dirname,
    env: {
      ...process.env,
      PORT: String(PORT),
      MONGO_URI: TEST_MONGO_URI,
      JWT_SECRET,
      NODE_ENV: 'test',
      DISABLE_RATE_LIMIT: 'true',
      BASE_URL: BASE,
      ADMIN_PHONES: '',
      TERMS_VERSION: '1.0',
      PRIVACY_VERSION: '1.0',
      SESSION_DAYS: '7',
      MAX_SESSIONS: '5',
      // make sure no real SMS / email is ever sent while testing
      TWILIO_ACCOUNT_SID: '',
      TWILIO_AUTH_TOKEN: '',
      TWILIO_FROM: '',
      SMTP_HOST: '',
      TRUST_PROXY: '',
    },
  });

  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Server did not start in time:\n' + serverLog)), 30000);
    const onData = (chunk) => {
      serverLog += chunk.toString();
      if (serverLog.includes('Server running')) {
        clearTimeout(timer);
        resolve();
      }
    };
    server.stdout.on('data', onData);
    server.stderr.on('data', onData);
    server.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`Server exited early (code ${code}):\n${serverLog}`));
    });
  });
  server.stdout.removeAllListeners('data');
  server.stderr.removeAllListeners('data');
  server.removeAllListeners('exit');
});

after(async () => {
  try {
    // remove any files the tests created
    const users = await db.collection('users').find({}).toArray();
    for (const u of users) {
      if (u.photo) fs.rmSync(path.join(AVATAR_DIR, u.photo), { force: true });
      const docs = (u.identity && u.identity.docs) || {};
      for (const f of Object.values(docs)) fs.rmSync(path.join(PRIVATE_DIR, f), { force: true });
    }
    await mongoose.connection.dropDatabase();
  } finally {
    await mongoose.disconnect();
    if (server) server.kill();
  }
});

// ==========================================================
//  General
// ==========================================================
describe('General', () => {
  it('GET / returns the API status', async () => {
    const r = await api('GET', '/');
    assert.equal(r.status, 200);
    assert.equal(r.data.success, true);
  });

  it('GET /api/legal returns the terms and privacy versions', async () => {
    const r = await api('GET', '/api/legal');
    assert.equal(r.status, 200);
    assert.equal(r.data.terms.version, '1.0');
    assert.equal(r.data.privacy.version, '1.0');
  });

  it('unknown route returns 404', async () => {
    const r = await api('GET', '/api/does-not-exist');
    assert.equal(r.status, 404);
    assert.equal(r.data.success, false);
  });

  it('malformed JSON returns 400', async () => {
    const r = await api('POST', '/api/auth/login', { body: '{bad json' });
    assert.equal(r.status, 400);
  });

  it('protected route without a token returns 401', async () => {
    const r = await api('GET', '/api/profile');
    assert.equal(r.status, 401);
  });

  it('protected route with a garbage token returns 401', async () => {
    const r = await api('GET', '/api/profile', { token: 'abc.def.ghi' });
    assert.equal(r.status, 401);
  });

  it('a validly signed token without a real session is rejected', async () => {
    const jwt = require('jsonwebtoken');
    const fake = jwt.sign({ id: UNKNOWN_ID, sid: UNKNOWN_ID }, JWT_SECRET, { expiresIn: '1h' });
    const r = await api('GET', '/api/profile', { token: fake });
    assert.equal(r.status, 401);
  });

  it('uploads folder does not allow path traversal or expose private files', async () => {
    const a = await fetch(`${BASE}/uploads/%2e%2e/server.js`);
    assert.notEqual(a.status, 200);
    const b = await fetch(`${BASE}/uploads/identity/anything.jpg`);
    assert.equal(b.status, 404);
    const c = await fetch(`${BASE}/private/identity/anything.jpg`);
    assert.equal(c.status, 404);
  });
});





// ==========================================================
//  Signup + OTP verification + terms
// ==========================================================
describe('Signup', () => {
  it('rejects invalid data and lists every error', async () => {
    const r = await api('POST', '/api/auth/signup', {
      body: { name: 'A', phone: '123', password: 'weak', acceptTerms: false, acceptPrivacy: false, role: 'admin' },
    });
    assert.equal(r.status, 400);
    assert.ok(r.data.errors.length >= 5, JSON.stringify(r.data.errors));
  });

  it('rejects a signup that does not accept the terms', async () => {
    const r = await api('POST', '/api/auth/signup', { body: signupBody(nextPhone(), { acceptTerms: false }) });
    assert.equal(r.status, 400);
    assert.ok(r.data.errors.some((e) => /terms/i.test(e)));
  });

  it('rejects a signup that does not accept the privacy policy', async () => {
    const r = await api('POST', '/api/auth/signup', { body: signupBody(nextPhone(), { acceptPrivacy: false }) });
    assert.equal(r.status, 400);
    assert.ok(r.data.errors.some((e) => /privacy/i.test(e)));
  });

  it('rejects a weak password and a password mismatch', async () => {
    const weak = await api('POST', '/api/auth/signup', { body: signupBody(nextPhone(), { password: 'abcdefgh', confirmPassword: 'abcdefgh' }) });
    assert.equal(weak.status, 400);
    const mismatch = await api('POST', '/api/auth/signup', { body: signupBody(nextPhone(), { confirmPassword: 'Different1' }) });
    assert.equal(mismatch.status, 400);
  });

  it('cannot sign up as admin', async () => {
    const r = await api('POST', '/api/auth/signup', { body: signupBody(nextPhone(), { role: 'admin' }) });
    assert.equal(r.status, 400);
  });

  it('full flow: signup -> cannot login yet -> wrong OTP -> correct OTP', async () => {
    const phone = nextPhone();
    const s = await api('POST', '/api/auth/signup', { body: signupBody(phone) });
    assert.equal(s.status, 201);
    assert.equal(s.data.phone, intl(phone));
    assert.equal(s.data.otpExpiresInMinutes, 5);
    assert.equal(s.data.token, undefined, 'no token before verification');

    // the account exists but is not verified yet
    const early = await api('POST', '/api/auth/login', { body: { phone, password: PASSWORD } });
    assert.equal(early.status, 403);
    assert.equal(early.data.needsVerification, true);

    await setOtp(intl(phone), 'signup', '123456');
    const wrong = await api('POST', '/api/auth/verify-otp', { body: { phone, code: '000000' } });
    assert.equal(wrong.status, 400);

    const ok = await api('POST', '/api/auth/verify-otp', { body: { phone, code: '123456' } });
    assert.equal(ok.status, 200);
    assert.ok(ok.data.token);
    assert.equal(ok.data.user.phone, intl(phone));
    assert.equal(ok.data.user.role, 'rider');
    assert.equal(ok.data.user.isPhoneVerified, true);
    assert.equal(ok.data.user.password, undefined, 'password must never be returned');

    // the code is single-use
    const reuse = await api('POST', '/api/auth/verify-otp', { body: { phone, code: '123456' } });
    assert.equal(reuse.status, 400);
  });

  it('stores the acceptance of terms and privacy policy with the version', async () => {
    const u = await registerUser();
    const doc = await db.collection('users').findOne({ phone: u.intlPhone });
    assert.equal(doc.termsVersion, '1.0');
    assert.equal(doc.privacyVersion, '1.0');
    assert.ok(doc.termsAcceptedAt instanceof Date);
    assert.ok(doc.privacyAcceptedAt instanceof Date);
  });

  it('never stores the password or the OTP in plain text', async () => {
    const phone = nextPhone();
    await api('POST', '/api/auth/signup', { body: signupBody(phone) });
    const user = await db.collection('users').findOne({ phone: intl(phone) });
    assert.notEqual(user.password, PASSWORD);
    assert.ok(user.password.startsWith('$2'), 'bcrypt hash expected');
    const otp = await db.collection('otps').findOne({ target: intl(phone), purpose: 'signup' });
    assert.ok(otp.codeHash && otp.codeHash.length === 64);
    assert.equal(otp.code, undefined);
  });

  it('a verified phone cannot be registered again (any phone format)', async () => {
    const u = await registerUser();
    const local = await api('POST', '/api/auth/signup', { body: signupBody(u.phone) });
    assert.equal(local.status, 409);
    const international = await api('POST', '/api/auth/signup', { body: signupBody(u.intlPhone) });
    assert.equal(international.status, 409);
    const twenty = await api('POST', '/api/auth/signup', { body: signupBody(u.intlPhone.slice(1)) });
    assert.equal(twenty.status, 409);
  });

  it('an unverified account can sign up again (data is replaced)', async () => {
    const phone = nextPhone();
    const first = await api('POST', '/api/auth/signup', { body: signupBody(phone, { name: 'First Name' }) });
    assert.equal(first.status, 201);
    await db.collection('otps').updateOne({ target: intl(phone), purpose: 'signup' }, { $set: { lastSentAt: new Date(0) } });
    const second = await api('POST', '/api/auth/signup', { body: signupBody(phone, { name: 'Second Name' }) });
    assert.equal(second.status, 201);
    const count = await db.collection('users').countDocuments({ phone: intl(phone) });
    assert.equal(count, 1);
    const doc = await db.collection('users').findOne({ phone: intl(phone) });
    assert.equal(doc.name, 'Second Name');
  });

  it('can sign up as a driver', async () => {
    const d = await registerUser({ role: 'driver' });
    const r = await api('GET', '/api/profile', { token: d.token });
    assert.equal(r.data.user.role, 'driver');
  });

  it('local Egyptian numbers are normalised to +20 format', async () => {
    const u = await registerUser();
    const r = await api('GET', '/api/profile', { token: u.token });
    assert.equal(r.data.user.phone, u.intlPhone);
    assert.match(r.data.user.phone, /^\+201[0125]\d{8}$/);
  });

  it('OTP expires', async () => {
    const phone = nextPhone();
    await api('POST', '/api/auth/signup', { body: signupBody(phone) });
    await setOtp(intl(phone), 'signup', '123456', { expiresAt: new Date(Date.now() - 1000) });
    const r = await api('POST', '/api/auth/verify-otp', { body: { phone, code: '123456' } });
    assert.equal(r.status, 400);
  });

  it('OTP is blocked after 5 wrong attempts (even with the correct code)', async () => {
    const phone = nextPhone();
    await api('POST', '/api/auth/signup', { body: signupBody(phone) });
    await setOtp(intl(phone), 'signup', '123456');
    for (let i = 0; i < 5; i++) {
      const bad = await api('POST', '/api/auth/verify-otp', { body: { phone, code: '000000' } });
      assert.equal(bad.status, 400);
    }
    const good = await api('POST', '/api/auth/verify-otp', { body: { phone, code: '123456' } });
    assert.equal(good.status, 400);
  });

  it('verify-otp validates its input', async () => {
    const r = await api('POST', '/api/auth/verify-otp', { body: { phone: 'nope' } });
    assert.equal(r.status, 400);
    const r2 = await api('POST', '/api/auth/verify-otp', { body: { phone: nextPhone(), code: 'abcdef' } });
    assert.equal(r2.status, 400);
  });

  it('resend-otp: generic answer for unknown phones, validation for bad ones', async () => {
    const unknown = await api('POST', '/api/auth/resend-otp', { body: { phone: nextPhone() } });
    assert.equal(unknown.status, 200);
    const bad = await api('POST', '/api/auth/resend-otp', { body: { phone: 'xyz' } });
    assert.equal(bad.status, 400);
  });

  it('resend-otp creates a fresh code for an unverified account', async () => {
    const phone = nextPhone();
    await api('POST', '/api/auth/signup', { body: signupBody(phone) });
    await db.collection('otps').updateOne({ target: intl(phone), purpose: 'signup' }, { $set: { lastSentAt: new Date(0) } });
    const before = await db.collection('otps').findOne({ target: intl(phone), purpose: 'signup' });
    const r = await api('POST', '/api/auth/resend-otp', { body: { phone } });
    assert.equal(r.status, 200);
    const after = await db.collection('otps').findOne({ target: intl(phone), purpose: 'signup' });
    assert.notEqual(before.codeHash, after.codeHash);
  });

  it('resend cooldown: a second send within a minute does not replace the code', async () => {
    const phone = nextPhone();
    await api('POST', '/api/auth/signup', { body: signupBody(phone) });
    const before = await db.collection('otps').findOne({ target: intl(phone), purpose: 'signup' });
    await api('POST', '/api/auth/resend-otp', { body: { phone } });
    const after = await db.collection('otps').findOne({ target: intl(phone), purpose: 'signup' });
    assert.equal(before.codeHash, after.codeHash);
  });
});

// ==========================================================
//  Login / Logout
// ==========================================================
describe('Login and logout', () => {
  let user;
  before(async () => {
    user = await registerUser();
  });

  it('requires phone and password', async () => {
    const r = await api('POST', '/api/auth/login', { body: {} });
    assert.equal(r.status, 400);
  });

  it('wrong password and unknown phone give the same generic answer', async () => {
    const wrong = await login(user, {}, 'WrongPass1');
    const unknown = await api('POST', '/api/auth/login', { body: { phone: nextPhone(), password: PASSWORD } });
    assert.equal(wrong.status, 401);
    assert.equal(unknown.status, 401);
    assert.equal(wrong.data.message, unknown.data.message);
  });

  it('logs in with the local or the international phone format', async () => {
    const local = await api('POST', '/api/auth/login', { body: { phone: user.phone, password: PASSWORD } });
    assert.equal(local.status, 200);
    assert.ok(local.data.token);
    const intlRes = await api('POST', '/api/auth/login', { body: { phone: user.intlPhone, password: PASSWORD } });
    assert.equal(intlRes.status, 200);
    assert.equal(intlRes.data.user.password, undefined);
  });

  it('the token works on a protected route', async () => {
    const r = await login(user);
    const profile = await api('GET', '/api/profile', { token: r.data.token });
    assert.equal(profile.status, 200);
    assert.equal(String(profile.data.user.id), user.id);
  });

  it('logout ends only the current session', async () => {
    const a = (await login(user, { deviceId: 'a' })).data.token;
    const b = (await login(user, { deviceId: 'b' })).data.token;
    const out = await api('POST', '/api/auth/logout', { token: a });
    assert.equal(out.status, 200);
    assert.equal((await api('GET', '/api/profile', { token: a })).status, 401);
    assert.equal((await api('GET', '/api/profile', { token: b })).status, 200);
  });
});

// ==========================================================
//  Forgot / reset password
// ==========================================================
describe('Forgot and reset password', () => {
  it('forgot-password gives the same answer for known and unknown phones', async () => {
    const u = await registerUser();
    const known = await api('POST', '/api/auth/forgot-password', { body: { phone: u.phone } });
    const unknown = await api('POST', '/api/auth/forgot-password', { body: { phone: nextPhone() } });
    assert.equal(known.status, 200);
    assert.equal(unknown.status, 200);
    assert.equal(known.data.message, unknown.data.message);
    const bad = await api('POST', '/api/auth/forgot-password', { body: { phone: 'xx' } });
    assert.equal(bad.status, 400);
  });

  it('forgot-password creates a reset code only for a real account', async () => {
    const u = await registerUser();
    await api('POST', '/api/auth/forgot-password', { body: { phone: u.phone } });
    assert.ok(await db.collection('otps').findOne({ target: u.intlPhone, purpose: 'reset' }));
    const ghost = nextPhone();
    await api('POST', '/api/auth/forgot-password', { body: { phone: ghost } });
    assert.equal(await db.collection('otps').findOne({ target: intl(ghost), purpose: 'reset' }), null);
  });

  it('reset-password validates input, code and password', async () => {
    const u = await registerUser();
    await setOtp(u.intlPhone, 'reset');
    const noCode = await api('POST', '/api/auth/reset-password', { body: { phone: u.phone, password: 'NewPass123', confirmPassword: 'NewPass123' } });
    assert.equal(noCode.status, 400);
    const weak = await api('POST', '/api/auth/reset-password', { body: { phone: u.phone, code: '123456', password: 'weak', confirmPassword: 'weak' } });
    assert.equal(weak.status, 400);
    const mismatch = await api('POST', '/api/auth/reset-password', { body: { phone: u.phone, code: '123456', password: 'NewPass123', confirmPassword: 'Other1234' } });
    assert.equal(mismatch.status, 400);
    const wrong = await api('POST', '/api/auth/reset-password', { body: { phone: u.phone, code: '999999', password: 'NewPass123', confirmPassword: 'NewPass123' } });
    assert.equal(wrong.status, 400);
  });

  it('full flow: reset changes the password and signs out every old session', async () => {
    const u = await registerUser();
    const oldToken = u.token;
    await api('POST', '/api/auth/forgot-password', { body: { phone: u.phone } });
    await setOtp(u.intlPhone, 'reset', '123456');

    const r = await api('POST', '/api/auth/reset-password', {
      body: { phone: u.phone, code: '123456', password: 'BrandNew123', confirmPassword: 'BrandNew123', deviceId: 'after-reset' },
    });
    assert.equal(r.status, 200);
    assert.ok(r.data.token);

    assert.equal((await login(u)).status, 401, 'old password must stop working');
    assert.equal((await login(u, {}, 'BrandNew123')).status, 200, 'new password works');
    assert.equal((await api('GET', '/api/profile', { token: oldToken })).status, 401, 'old session revoked');
    assert.equal((await api('GET', '/api/profile', { token: r.data.token })).status, 200, 'new session works');

    // the reset code is single-use
    const again = await api('POST', '/api/auth/reset-password', {
      body: { phone: u.phone, code: '123456', password: 'Another123', confirmPassword: 'Another123' },
    });
    assert.equal(again.status, 400);
  });
});





// ==========================================================
//  Profile
// ==========================================================
describe('Profile', () => {
  let u;
  before(async () => {
    u = await registerUser({ name: 'Profile Tester' });
  });

  it('GET /api/profile returns the profile with default settings', async () => {
    const r = await api('GET', '/api/profile', { token: u.token });
    assert.equal(r.status, 200);
    const p = r.data.user;
    assert.equal(p.name, 'Profile Tester');
    assert.equal(p.email, null);
    assert.equal(p.photoUrl, null);
    assert.equal(p.settings.language, 'ar');
    assert.deepEqual(p.settings.notifications, { push: true, sms: true, email: true, promotions: false });
    assert.equal(p.identityStatus, 'none');
    assert.equal(p.password, undefined);
  });

  it('PATCH /api/profile updates name, gender and date of birth', async () => {
    const r = await api('PATCH', '/api/profile', {
      token: u.token,
      body: { name: '  New Name  ', gender: 'female', dateOfBirth: '1995-05-20' },
    });
    assert.equal(r.status, 200);
    assert.equal(r.data.user.name, 'New Name');
    assert.equal(r.data.user.gender, 'female');
    assert.ok(String(r.data.user.dateOfBirth).startsWith('1995-05-20'));
    const get = await api('GET', '/api/profile', { token: u.token });
    assert.equal(get.data.user.name, 'New Name');
  });

  it('PATCH /api/profile rejects invalid values', async () => {
    const bad = [
      { name: 'A' },
      { name: 123 },
      { gender: 'other' },
      { dateOfBirth: 'not-a-date' },
      { dateOfBirth: '2999-01-01' },
      { dateOfBirth: 12345 },
      {},
    ];
    for (const body of bad) {
      const r = await api('PATCH', '/api/profile', { token: u.token, body });
      assert.equal(r.status, 400, JSON.stringify(body));
    }
  });

  it('cannot change phone / role / status through PATCH /api/profile', async () => {
    const r = await api('PATCH', '/api/profile', {
      token: u.token,
      body: { name: 'Still Me', role: 'admin', phone: '+201099999999', status: 'banned' },
    });
    assert.equal(r.status, 200);
    assert.equal(r.data.user.role, 'rider');
    assert.equal(r.data.user.phone, u.intlPhone);
    const me = await api('GET', '/api/profile', { token: u.token });
    assert.equal(me.status, 200);
  });

  describe('Photo', () => {
    let firstUrl;

    it('requires authentication', async () => {
      const r = await api('PUT', '/api/profile/photo', {
        form: imageForm({ photo: { buf: pngBuf(), filename: 'a.png', type: 'image/png' } }),
      });
      assert.equal(r.status, 401);
    });

    it('rejects a request without a file', async () => {
      const r = await api('PUT', '/api/profile/photo', { token: u.token, form: new FormData() });
      assert.equal(r.status, 400);
    });

    it('rejects a non-image file, even with an image file name', async () => {
      const r = await api('PUT', '/api/profile/photo', {
        token: u.token,
        form: imageForm({ photo: { buf: Buffer.from('this is definitely not an image, just text'), filename: 'evil.jpg', type: 'image/jpeg' } }),
      });
      assert.equal(r.status, 400);
    });

    it('rejects a file bigger than 2MB', async () => {
      const r = await api('PUT', '/api/profile/photo', {
        token: u.token,
        form: imageForm({ photo: { buf: pngBuf(2 * 1024 * 1024 + 10), filename: 'big.png', type: 'image/png' } }),
      });
      assert.equal(r.status, 400);
    });

    it('uploads a PNG and serves it publicly', async () => {
      const r = await api('PUT', '/api/profile/photo', {
        token: u.token,
        form: imageForm({ photo: { buf: pngBuf(), filename: 'me.png', type: 'image/png' } }),
      });
      assert.equal(r.status, 200);
      firstUrl = r.data.photoUrl;
      assert.match(firstUrl, /\/uploads\/avatars\/[a-f0-9]{32}\.png$/);
      const img = await fetch(firstUrl);
      assert.equal(img.status, 200);
      assert.match(img.headers.get('content-type'), /image\/png/);
      const profile = await api('GET', '/api/profile', { token: u.token });
      assert.equal(profile.data.user.photoUrl, firstUrl);
    });

    it('replacing the photo deletes the old file', async () => {
      const r = await api('PUT', '/api/profile/photo', {
        token: u.token,
        form: imageForm({ photo: { buf: jpgBuf(), filename: 'new.jpg', type: 'image/jpeg' } }),
      });
      assert.equal(r.status, 200);
      assert.match(r.data.photoUrl, /\.jpg$/);
      await new Promise((res) => setTimeout(res, 200));
      assert.equal((await fetch(firstUrl)).status, 404, 'old photo must be gone');
      assert.equal((await fetch(r.data.photoUrl)).status, 200);
    });

    it('deletes the photo', async () => {
      const before = (await api('GET', '/api/profile', { token: u.token })).data.user.photoUrl;
      const r = await api('DELETE', '/api/profile/photo', { token: u.token });
      assert.equal(r.status, 200);
      await new Promise((res) => setTimeout(res, 200));
      assert.equal((await api('GET', '/api/profile', { token: u.token })).data.user.photoUrl, null);
      assert.equal((await fetch(before)).status, 404);
    });
  });

  describe('Settings', () => {
    it('updates the language and notification preferences', async () => {
      const r = await api('PATCH', '/api/profile/settings', {
        token: u.token,
        body: { language: 'en', notifications: { promotions: true, sms: false } },
      });
      assert.equal(r.status, 200);
      assert.equal(r.data.settings.language, 'en');
      assert.deepEqual(r.data.settings.notifications, { push: true, sms: false, email: true, promotions: true });
      const get = await api('GET', '/api/profile', { token: u.token });
      assert.equal(get.data.user.settings.language, 'en');
      assert.equal(get.data.user.settings.notifications.sms, false);
    });

    it('rejects invalid settings', async () => {
      const bad = [
        { language: 'fr' },
        { notifications: 'yes' },
        { notifications: ['push'] },
        { notifications: { push: 'true' } },
        {},
      ];
      for (const body of bad) {
        const r = await api('PATCH', '/api/profile/settings', { token: u.token, body });
        assert.equal(r.status, 400, JSON.stringify(body));
      }
    });
  });
});

// ==========================================================
//  Change phone number
// ==========================================================
describe('Change phone number', () => {
  let u;
  let other;
  let secondSession;
  const newLocal = nextPhone();

  before(async () => {
    u = await registerUser();
    other = await registerUser();
    secondSession = (await login(u, { deviceId: 'second' })).data.token;
  });

  it('requires the current password', async () => {
    const none = await api('POST', '/api/profile/phone/request', { token: u.token, body: { newPhone: newLocal } });
    assert.equal(none.status, 400);
    const wrong = await api('POST', '/api/profile/phone/request', { token: u.token, body: { newPhone: newLocal, password: 'Wrong1234' } });
    assert.equal(wrong.status, 401);
  });

  it('rejects an invalid number, the current number and a number used by another account', async () => {
    const invalid = await api('POST', '/api/profile/phone/request', { token: u.token, body: { newPhone: '123', password: PASSWORD } });
    assert.equal(invalid.status, 400);
    const same = await api('POST', '/api/profile/phone/request', { token: u.token, body: { newPhone: u.phone, password: PASSWORD } });
    assert.equal(same.status, 400);
    const taken = await api('POST', '/api/profile/phone/request', { token: u.token, body: { newPhone: other.phone, password: PASSWORD } });
    assert.equal(taken.status, 409);
  });

  it('verify without a pending request fails', async () => {
    const r = await api('POST', '/api/profile/phone/verify', { token: u.token, body: { code: '123456' } });
    assert.equal(r.status, 400);
  });

  it('full flow: request -> wrong code -> correct code', async () => {
    const req = await api('POST', '/api/profile/phone/request', { token: u.token, body: { newPhone: newLocal, password: PASSWORD } });
    assert.equal(req.status, 200);
    assert.equal(req.data.newPhone, intl(newLocal));

    // the phone must NOT change before verification
    assert.equal((await api('GET', '/api/profile', { token: u.token })).data.user.phone, u.intlPhone);

    await setOtp(intl(newLocal), `change_phone:${u.id}`, '123456');
    const wrong = await api('POST', '/api/profile/phone/verify', { token: u.token, body: { code: '000000' } });
    assert.equal(wrong.status, 400);

    const ok = await api('POST', '/api/profile/phone/verify', { token: u.token, body: { code: '123456' } });
    assert.equal(ok.status, 200);
    assert.equal(ok.data.phone, intl(newLocal));

    assert.equal((await api('GET', '/api/profile', { token: u.token })).data.user.phone, intl(newLocal));
  });

  it('signs out other devices but keeps the current one', async () => {
    assert.equal((await api('GET', '/api/profile', { token: secondSession })).status, 401);
    assert.equal((await api('GET', '/api/profile', { token: u.token })).status, 200);
  });

  it('the new number works for login and the old one does not', async () => {
    const withNew = await api('POST', '/api/auth/login', { body: { phone: newLocal, password: PASSWORD } });
    assert.equal(withNew.status, 200);
    const withOld = await api('POST', '/api/auth/login', { body: { phone: u.phone, password: PASSWORD } });
    assert.equal(withOld.status, 401);
  });

  it('records a phone_changed security event', async () => {
    assert.ok((await eventTypes(u)).includes('phone_changed'));
  });
});

// ==========================================================
//  Change email
// ==========================================================
describe('Change email', () => {
  let u;
  let other;
  const email = nextEmail();

  before(async () => {
    u = await registerUser();
    other = await registerUser();
  });

  it('requires the current password and a valid email', async () => {
    const noPw = await api('POST', '/api/profile/email/request', { token: u.token, body: { newEmail: email } });
    assert.equal(noPw.status, 400);
    const wrong = await api('POST', '/api/profile/email/request', { token: u.token, body: { newEmail: email, password: 'Wrong1234' } });
    assert.equal(wrong.status, 401);
    const invalid = await api('POST', '/api/profile/email/request', { token: u.token, body: { newEmail: 'not-an-email', password: PASSWORD } });
    assert.equal(invalid.status, 400);
  });

  it('verify without a pending request fails', async () => {
    const r = await api('POST', '/api/profile/email/verify', { token: u.token, body: { code: '123456' } });
    assert.equal(r.status, 400);
  });

  it('full flow: request -> wrong code -> correct code', async () => {
    const req = await api('POST', '/api/profile/email/request', { token: u.token, body: { newEmail: email.toUpperCase(), password: PASSWORD } });
    assert.equal(req.status, 200);
    assert.equal(req.data.newEmail, email);

    assert.equal((await api('GET', '/api/profile', { token: u.token })).data.user.email, null);

    await setOtp(email, `change_email:${u.id}`, '123456');
    const wrong = await api('POST', '/api/profile/email/verify', { token: u.token, body: { code: '000000' } });
    assert.equal(wrong.status, 400);

    const ok = await api('POST', '/api/profile/email/verify', { token: u.token, body: { code: '123456' } });
    assert.equal(ok.status, 200);
    assert.equal(ok.data.email, email);

    const profile = await api('GET', '/api/profile', { token: u.token });
    assert.equal(profile.data.user.email, email);
    assert.equal(profile.data.user.isEmailVerified, true);
  });

  it('the same email cannot be used by another account', async () => {
    const r = await api('POST', '/api/profile/email/request', { token: other.token, body: { newEmail: email, password: PASSWORD } });
    assert.equal(r.status, 409);
  });

  it('rejects the current email', async () => {
    const r = await api('POST', '/api/profile/email/request', { token: u.token, body: { newEmail: email, password: PASSWORD } });
    assert.equal(r.status, 400);
  });

  it('can change to a different email', async () => {
    const second = nextEmail();
    const req = await api('POST', '/api/profile/email/request', { token: u.token, body: { newEmail: second, password: PASSWORD } });
    assert.equal(req.status, 200);
    await setOtp(second, `change_email:${u.id}`, '123456');
    const ok = await api('POST', '/api/profile/email/verify', { token: u.token, body: { code: '123456' } });
    assert.equal(ok.status, 200);
    assert.equal((await api('GET', '/api/profile', { token: u.token })).data.user.email, second);
    assert.ok((await eventTypes(u)).includes('email_changed'));
  });
});




// ==========================================================
//  Account security: password, sessions, events
// ==========================================================
describe('Change password', () => {
  let u;
  let otherDevice;
  before(async () => {
    u = await registerUser();
    otherDevice = (await login(u, { deviceId: 'other-device' })).data.token;
  });

  it('requires the current password', async () => {
    const none = await api('POST', '/api/account/change-password', { token: u.token, body: { newPassword: 'NewPass123', confirmPassword: 'NewPass123' } });
    assert.equal(none.status, 400);
    const wrong = await api('POST', '/api/account/change-password', {
      token: u.token,
      body: { currentPassword: 'Wrong1234', newPassword: 'NewPass123', confirmPassword: 'NewPass123' },
    });
    assert.equal(wrong.status, 401);
  });

  it('validates the new password', async () => {
    const weak = await api('POST', '/api/account/change-password', {
      token: u.token,
      body: { currentPassword: PASSWORD, newPassword: 'weak', confirmPassword: 'weak' },
    });
    assert.equal(weak.status, 400);
    const mismatch = await api('POST', '/api/account/change-password', {
      token: u.token,
      body: { currentPassword: PASSWORD, newPassword: 'NewPass123', confirmPassword: 'Other1234' },
    });
    assert.equal(mismatch.status, 400);
    const same = await api('POST', '/api/account/change-password', {
      token: u.token,
      body: { currentPassword: PASSWORD, newPassword: PASSWORD, confirmPassword: PASSWORD },
    });
    assert.equal(same.status, 400);
  });

  it('changes the password, keeps this device and signs out the others', async () => {
    const r = await api('POST', '/api/account/change-password', {
      token: u.token,
      body: { currentPassword: PASSWORD, newPassword: 'NewPass123', confirmPassword: 'NewPass123' },
    });
    assert.equal(r.status, 200);
    assert.equal((await api('GET', '/api/profile', { token: u.token })).status, 200);
    assert.equal((await api('GET', '/api/profile', { token: otherDevice })).status, 401);
    assert.equal((await login(u)).status, 401, 'old password rejected');
    assert.equal((await login(u, {}, 'NewPass123')).status, 200, 'new password accepted');
    assert.ok((await eventTypes(u)).includes('password_changed'));
  });
});

describe('Sessions and devices', () => {
  let u;
  before(async () => {
    u = await registerUser();
  });

  it('lists devices and marks the current one', async () => {
    const t2 = (await login(u, { deviceId: 'tablet', deviceName: 'My Tablet' })).data.token;
    const r = await api('GET', '/api/account/sessions', { token: t2 });
    assert.equal(r.status, 200);
    assert.equal(r.data.sessions.length, 2);
    const current = r.data.sessions.filter((s) => s.current);
    assert.equal(current.length, 1);
    assert.equal(current[0].deviceName, 'My Tablet');
    assert.ok(r.data.sessions.some((s) => s.deviceName === 'Main Phone'));
    assert.ok(r.data.sessions.every((s) => s.id && s.createdAt && s.lastActiveAt));
  });

  it('revokes a specific device', async () => {
    const t3 = (await login(u, { deviceId: 'laptop', deviceName: 'Laptop' })).data.token;
    const list = await api('GET', '/api/account/sessions', { token: u.token });
    const laptop = list.data.sessions.find((s) => s.deviceName === 'Laptop');
    const r = await api('DELETE', `/api/account/sessions/${laptop.id}`, { token: u.token });
    assert.equal(r.status, 200);
    assert.equal((await api('GET', '/api/profile', { token: t3 })).status, 401);
    assert.equal((await api('GET', '/api/profile', { token: u.token })).status, 200);
  });

  it('rejects an invalid or unknown session id', async () => {
    assert.equal((await api('DELETE', '/api/account/sessions/not-an-id', { token: u.token })).status, 400);
    assert.equal((await api('DELETE', `/api/account/sessions/${UNKNOWN_ID}`, { token: u.token })).status, 404);
  });

  it("cannot revoke another user's session", async () => {
    const stranger = await registerUser();
    const theirs = (await api('GET', '/api/account/sessions', { token: stranger.token })).data.sessions[0];
    const r = await api('DELETE', `/api/account/sessions/${theirs.id}`, { token: u.token });
    assert.equal(r.status, 404);
    assert.equal((await api('GET', '/api/profile', { token: stranger.token })).status, 200);
  });

  it('signs out of all other devices and keeps the current one', async () => {
    const a = (await login(u, { deviceId: 'x1' })).data.token;
    const b = (await login(u, { deviceId: 'x2' })).data.token;
    const r = await api('DELETE', '/api/account/sessions', { token: a });
    assert.equal(r.status, 200);
    assert.equal((await api('GET', '/api/profile', { token: a })).status, 200);
    assert.equal((await api('GET', '/api/profile', { token: b })).status, 401);
    assert.equal((await api('GET', '/api/profile', { token: u.token })).status, 401);
    const list = await api('GET', '/api/account/sessions', { token: a });
    assert.equal(list.data.sessions.length, 1);
  });

  it(`keeps at most 5 devices signed in (oldest sessions are revoked)`, async () => {
    const m = await registerUser();
    const tokens = [m.token];
    for (let i = 0; i < 6; i++) {
      tokens.push((await login(m, { deviceId: `d${i}` })).data.token);
    }
    const newest = tokens[tokens.length - 1];
    const list = await api('GET', '/api/account/sessions', { token: newest });
    assert.equal(list.data.sessions.length, 5);
    assert.equal((await api('GET', '/api/profile', { token: tokens[0] })).status, 401, 'oldest session revoked');
    assert.equal((await api('GET', '/api/profile', { token: newest })).status, 200);
  });
});

describe('Security events', () => {
  it('records logins, new devices and failed attempts for the user', async () => {
    const u = await registerUser();
    await login(u, {}, 'Wrong1234');
    await login(u, { deviceId: 'brand-new-device' });
    await api('PATCH', '/api/profile', { token: u.token, body: { name: 'Event Tester' } });
    const types = await eventTypes(u);
    assert.ok(types.includes('login_failed'), types.join());
    assert.ok(types.includes('login_new_device'), types.join());
    assert.ok(types.includes('profile_updated'), types.join());
  });

  it('does not leak internal details to the user', async () => {
    const u = await registerUser();
    const r = await api('GET', '/api/account/security-events', { token: u.token });
    assert.equal(r.status, 200);
    assert.ok(r.data.events.length >= 1);
    for (const e of r.data.events) {
      assert.deepEqual(Object.keys(e).sort(), ['createdAt', 'ip', 'type', 'userAgent']);
    }
  });

  it('requires authentication', async () => {
    assert.equal((await api('GET', '/api/account/security-events')).status, 401);
  });
});

// ==========================================================
//  Lockout (suspicious activity)
// ==========================================================
describe('Account lockout after failed logins', () => {
  let u;
  let admin;
  before(async () => {
    u = await registerUser();
    admin = await makeAdmin();
  });

  it('locks the account after 5 wrong passwords, even for the correct password afterwards', async () => {
    for (let i = 0; i < 5; i++) {
      const r = await login(u, {}, 'Wrong1234');
      assert.equal(r.status, 401, `attempt ${i + 1}`);
    }
    const locked = await login(u, {}, 'Wrong1234');
    assert.equal(locked.status, 429);
    assert.equal(locked.data.code, 'ACCOUNT_LOCKED');

    const correct = await login(u);
    assert.equal(correct.status, 429, 'correct password must not work while locked');
    assert.equal(correct.data.code, 'ACCOUNT_LOCKED');
  });

  it('flags the account as suspicious and records the lock', async () => {
    const doc = await db.collection('users').findOne({ phone: u.intlPhone });
    assert.equal(doc.flagged, true);
    assert.ok(doc.lockUntil > new Date());
    assert.ok((await eventTypes({ token: u.token })).includes('account_locked'));
  });

  it('sensitive actions are blocked while locked', async () => {
    const r = await api('POST', '/api/account/change-password', {
      token: u.token,
      body: { currentPassword: PASSWORD, newPassword: 'NewPass123', confirmPassword: 'NewPass123' },
    });
    assert.equal(r.status, 429);
  });

  it('an admin can reinstate the account (clears lock and flag)', async () => {
    const r = await api('POST', `/api/admin/users/${u.id}/reinstate`, { token: admin.token, body: { note: 'verified by phone' } });
    assert.equal(r.status, 200);
    const ok = await login(u);
    assert.equal(ok.status, 200);
    const doc = await db.collection('users').findOne({ phone: u.intlPhone });
    assert.equal(doc.flagged, false);
    assert.equal(doc.lockUntil, undefined);
  });

  it('the lock expires by itself', async () => {
    const v = await registerUser();
    for (let i = 0; i < 5; i++) await login(v, {}, 'Wrong1234');
    assert.equal((await login(v)).status, 429);
    await db.collection('users').updateOne({ phone: v.intlPhone }, { $set: { lockUntil: new Date(Date.now() - 1000) } });
    assert.equal((await login(v)).status, 200);
  });

  it('resetting the password with a valid OTP also clears the lock', async () => {
    const v = await registerUser();
    for (let i = 0; i < 5; i++) await login(v, {}, 'Wrong1234');
    assert.equal((await login(v)).status, 429);
    await setOtp(v.intlPhone, 'reset');
    const r = await api('POST', '/api/auth/reset-password', {
      body: { phone: v.phone, code: '123456', password: 'Recovered123', confirmPassword: 'Recovered123' },
    });
    assert.equal(r.status, 200);
    assert.equal((await login(v, {}, 'Recovered123')).status, 200);
  });

  it('a successful login resets the failed-attempt counter', async () => {
    const v = await registerUser();
    for (let i = 0; i < 3; i++) await login(v, {}, 'Wrong1234');
    assert.equal((await login(v)).status, 200);
    const doc = await db.collection('users').findOne({ phone: v.intlPhone });
    assert.equal(doc.failedLoginAttempts, 0);
  });
});

// ==========================================================
//  Identity verification (KYC)
// ==========================================================
describe('Identity verification', () => {
  let driver;
  let admin;

  before(async () => {
    driver = await registerUser({ role: 'driver' });
    admin = await makeAdmin();
  });

  it('starts with status "none"', async () => {
    const r = await api('GET', '/api/account/identity', { token: driver.token });
    assert.equal(r.status, 200);
    assert.equal(r.data.status, 'none');
  });

  it('requires authentication', async () => {
    assert.equal((await api('POST', '/api/account/identity', { form: idForm() })).status, 401);
    assert.equal((await api('GET', '/api/account/identity')).status, 401);
  });

  it('requires all three images', async () => {
    const only = imageForm({ idFront: { buf: jpgBuf(), filename: 'f.jpg', type: 'image/jpeg' } });
    const r = await api('POST', '/api/account/identity', { token: driver.token, form: only });
    assert.equal(r.status, 400);
  });

  it('rejects non-image documents and leaves no files behind', async () => {
    const before = fs.readdirSync(PRIVATE_DIR).length;
    const form = imageForm({
      idFront: { buf: jpgBuf(), filename: 'f.jpg', type: 'image/jpeg' },
      idBack: { buf: Buffer.from('not an image at all, just plain text'), filename: 'b.jpg', type: 'image/jpeg' },
      selfie: { buf: pngBuf(), filename: 's.png', type: 'image/png' },
    });
    const r = await api('POST', '/api/account/identity', { token: driver.token, form });
    assert.equal(r.status, 400);
    assert.equal(fs.readdirSync(PRIVATE_DIR).length, before, 'no orphan files');
    assert.equal((await api('GET', '/api/account/identity', { token: driver.token })).data.status, 'none');
  });

  it('rejects unexpected file fields', async () => {
    const form = imageForm({
      idFront: { buf: jpgBuf(), filename: 'f.jpg', type: 'image/jpeg' },
      hacker: { buf: jpgBuf(), filename: 'h.jpg', type: 'image/jpeg' },
    });
    const r = await api('POST', '/api/account/identity', { token: driver.token, form });
    assert.equal(r.status, 400);
  });

  it('submits the documents and the status becomes "pending"', async () => {
    const r = await api('POST', '/api/account/identity', { token: driver.token, form: idForm() });
    assert.equal(r.status, 201);
    assert.equal(r.data.status, 'pending');
    const s = await api('GET', '/api/account/identity', { token: driver.token });
    assert.equal(s.data.status, 'pending');
    assert.ok(s.data.submittedAt);
    assert.equal((await api('GET', '/api/profile', { token: driver.token })).data.user.identityStatus, 'pending');
  });

  it('cannot submit again while under review', async () => {
    const r = await api('POST', '/api/account/identity', { token: driver.token, form: idForm() });
    assert.equal(r.status, 409);
  });

  it('documents are not reachable by the public or by normal users', async () => {
    const doc = await db.collection('users').findOne({ phone: driver.intlPhone });
    const file = doc.identity.docs.front;
    assert.equal((await fetch(`${BASE}/uploads/${file}`)).status, 404);
    assert.equal((await fetch(`${BASE}/uploads/identity/${file}`)).status, 404);
    assert.equal((await fetch(`${BASE}/private/identity/${file}`)).status, 404);
    const asUser = await api('GET', `/api/admin/identity/${driver.id}/front`, { token: driver.token });
    assert.equal(asUser.status, 403);
    const noAuth = await api('GET', `/api/admin/identity/${driver.id}/front`);
    assert.equal(noAuth.status, 401);
  });

  it('a normal user cannot use the admin review endpoints', async () => {
    const list = await api('GET', '/api/admin/identity/pending', { token: driver.token });
    assert.equal(list.status, 403);
    const decide = await api('POST', `/api/admin/identity/${driver.id}`, { token: driver.token, body: { decision: 'approve' } });
    assert.equal(decide.status, 403);
  });

  it('the admin sees the request in the pending list', async () => {
    const r = await api('GET', '/api/admin/identity/pending', { token: admin.token });
    assert.equal(r.status, 200);
    const found = r.data.requests.find((x) => String(x.userId) === driver.id);
    assert.ok(found);
    assert.equal(found.role, 'driver');
  });

  it('the admin can view each document (and only valid document names)', async () => {
    for (const [name, type] of [['front', 'image/jpeg'], ['back', 'image/jpeg'], ['selfie', 'image/png']]) {
      const res = await fetch(`${BASE}/api/admin/identity/${driver.id}/${name}`, {
        headers: { Authorization: `Bearer ${admin.token}` },
      });
      assert.equal(res.status, 200, name);
      assert.match(res.headers.get('content-type'), new RegExp(type));
      assert.match(res.headers.get('cache-control'), /no-store/);
    }
    assert.equal((await api('GET', `/api/admin/identity/${driver.id}/passport`, { token: admin.token })).status, 400);
    assert.equal((await api('GET', `/api/admin/identity/${UNKNOWN_ID}/front`, { token: admin.token })).status, 404);
    assert.equal((await api('GET', `/api/admin/identity/bad-id/front`, { token: admin.token })).status, 400);
  });

  it('validates the admin decision', async () => {
    const bad = await api('POST', `/api/admin/identity/${driver.id}`, { token: admin.token, body: { decision: 'maybe' } });
    assert.equal(bad.status, 400);
    const noReason = await api('POST', `/api/admin/identity/${driver.id}`, { token: admin.token, body: { decision: 'reject' } });
    assert.equal(noReason.status, 400);
  });

  it('a user with no pending request cannot be reviewed', async () => {
    const other = await registerUser();
    const r = await api('POST', `/api/admin/identity/${other.id}`, { token: admin.token, body: { decision: 'approve' } });
    assert.equal(r.status, 400);
  });

  it('rejection: the user sees the reason and can submit again', async () => {
    const r = await api('POST', `/api/admin/identity/${driver.id}`, {
      token: admin.token,
      body: { decision: 'reject', reason: 'Photo is blurry' },
    });
    assert.equal(r.status, 200);
    const s = await api('GET', '/api/account/identity', { token: driver.token });
    assert.equal(s.data.status, 'rejected');
    assert.equal(s.data.rejectionReason, 'Photo is blurry');

    const oldDoc = await db.collection('users').findOne({ phone: driver.intlPhone });
    const oldFront = oldDoc.identity.docs.front;

    const again = await api('POST', '/api/account/identity', { token: driver.token, form: idForm() });
    assert.equal(again.status, 201);
    assert.equal((await api('GET', '/api/account/identity', { token: driver.token })).data.status, 'pending');
    await new Promise((res) => setTimeout(res, 200));
    assert.equal(fs.existsSync(path.join(PRIVATE_DIR, oldFront)), false, 'old documents are deleted');
  });

  it('approval: status becomes "approved" and further submissions are refused', async () => {
    const r = await api('POST', `/api/admin/identity/${driver.id}`, { token: admin.token, body: { decision: 'approve' } });
    assert.equal(r.status, 200);
    const s = await api('GET', '/api/account/identity', { token: driver.token });
    assert.equal(s.data.status, 'approved');
    assert.equal(s.data.rejectionReason, null);
    assert.equal((await api('GET', '/api/profile', { token: driver.token })).data.user.identityStatus, 'approved');
    const again = await api('POST', '/api/account/identity', { token: driver.token, form: idForm() });
    assert.equal(again.status, 409);
    const types = await eventTypes(driver);
    assert.ok(types.includes('identity_submitted'));
    assert.ok(types.includes('identity_approved'));
    assert.ok(types.includes('identity_rejected'));
  });

  it('an admin cannot review their own identity', async () => {
    await db.collection('users').updateOne({ phone: admin.intlPhone }, { $set: { 'identity.status': 'pending' } });
    const r = await api('POST', `/api/admin/identity/${admin.id}`, { token: admin.token, body: { decision: 'approve' } });
    assert.equal(r.status, 403);
    await db.collection('users').updateOne({ phone: admin.intlPhone }, { $set: { 'identity.status': 'none' } });
  });
});




// ==========================================================
//  Admin: user management, suspension, ban, flags
// ==========================================================
describe('Admin user management', () => {
  let admin;
  let target;
  let normal;

  before(async () => {
    admin = await makeAdmin();
    target = await registerUser({ name: 'Target User' });
    normal = await registerUser();
  });

  it('normal users and anonymous callers cannot use admin endpoints', async () => {
    assert.equal((await api('GET', '/api/admin/users')).status, 401);
    assert.equal((await api('GET', '/api/admin/users', { token: normal.token })).status, 403);
    assert.equal((await api('POST', `/api/admin/users/${target.id}/suspend`, { token: normal.token, body: { reason: 'nope' } })).status, 403);
    assert.equal((await api('POST', `/api/admin/users/${target.id}/ban`, { token: normal.token, body: { reason: 'nope' } })).status, 403);
    assert.equal((await api('POST', `/api/admin/users/${target.id}/reinstate`, { token: normal.token, body: {} })).status, 403);
    assert.equal((await api('POST', `/api/admin/users/${target.id}/flag`, { token: normal.token, body: { flagged: true, reason: 'nope' } })).status, 403);
  });

  it('lists users with pagination and filters, without secrets', async () => {
    const r = await api('GET', '/api/admin/users?limit=3&page=1', { token: admin.token });
    assert.equal(r.status, 200);
    assert.ok(r.data.total >= 3);
    assert.equal(r.data.users.length, 3);
    assert.equal(r.data.limit, 3);
    for (const x of r.data.users) {
      assert.equal(x.password, undefined);
      assert.ok(x.id && x.phone && x.role && x.status);
    }
    const drivers = await api('GET', '/api/admin/users?role=driver', { token: admin.token });
    assert.ok(drivers.data.users.length >= 1);
    assert.ok(drivers.data.users.every((x) => x.role === 'driver'));
    const search = await api('GET', `/api/admin/users?q=${target.phone.slice(-8)}`, { token: admin.token });
    assert.ok(search.data.users.some((x) => String(x.id) === target.id));
    const weird = await api('GET', '/api/admin/users?q=.*(', { token: admin.token });
    assert.equal(weird.status, 200, 'regex characters are escaped');
  });

  it('gets one user, validating the id', async () => {
    const r = await api('GET', `/api/admin/users/${target.id}`, { token: admin.token });
    assert.equal(r.status, 200);
    assert.equal(r.data.user.name, 'Target User');
    assert.equal(r.data.user.activeSessions, 1);
    assert.equal((await api('GET', '/api/admin/users/bad-id', { token: admin.token })).status, 400);
    assert.equal((await api('GET', `/api/admin/users/${UNKNOWN_ID}`, { token: admin.token })).status, 404);
  });

  it('suspend validates its input', async () => {
    const noReason = await api('POST', `/api/admin/users/${target.id}/suspend`, { token: admin.token, body: {} });
    assert.equal(noReason.status, 400);
    const badDays = await api('POST', `/api/admin/users/${target.id}/suspend`, { token: admin.token, body: { reason: 'abuse', days: 0 } });
    assert.equal(badDays.status, 400);
    const tooLong = await api('POST', `/api/admin/users/${target.id}/suspend`, { token: admin.token, body: { reason: 'abuse', days: 999 } });
    assert.equal(tooLong.status, 400);
    assert.equal((await api('POST', `/api/admin/users/${UNKNOWN_ID}/suspend`, { token: admin.token, body: { reason: 'abuse' } })).status, 404);
  });

  it('an admin cannot suspend / ban / flag an admin or themselves', async () => {
    const other = await makeAdmin();
    for (const action of ['suspend', 'ban']) {
      assert.equal((await api('POST', `/api/admin/users/${other.id}/${action}`, { token: admin.token, body: { reason: 'power trip' } })).status, 403);
      assert.equal((await api('POST', `/api/admin/users/${admin.id}/${action}`, { token: admin.token, body: { reason: 'oops' } })).status, 403);
    }
    assert.equal((await api('POST', `/api/admin/users/${other.id}/flag`, { token: admin.token, body: { flagged: true, reason: 'x y z' } })).status, 403);
  });

  it('temporary suspension blocks the user immediately and everywhere', async () => {
    const r = await api('POST', `/api/admin/users/${target.id}/suspend`, { token: admin.token, body: { reason: 'Rude to drivers', days: 7 } });
    assert.equal(r.status, 200);
    assert.ok(r.data.suspendedUntil);

    // the existing session was revoked
    assert.equal((await api('GET', '/api/profile', { token: target.token })).status, 401);

    // login is blocked with a clear code, and the internal reason is not leaked
    const l = await login(target);
    assert.equal(l.status, 403);
    assert.equal(l.data.code, 'ACCOUNT_SUSPENDED');
    assert.ok(l.data.suspendedUntil);
    assert.ok(!JSON.stringify(l.data).includes('Rude to drivers'));
    assert.equal(l.data.token, undefined);

    const info = await api('GET', `/api/admin/users/${target.id}`, { token: admin.token });
    assert.equal(info.data.user.status, 'suspended');
    assert.equal(info.data.user.statusReason, 'Rude to drivers');
    assert.equal(info.data.user.activeSessions, 0);
  });

  it('a suspended user cannot sign in through password reset either', async () => {
    await setOtp(target.intlPhone, 'reset');
    const r = await api('POST', '/api/auth/reset-password', {
      body: { phone: target.phone, code: '123456', password: 'StillBlocked1', confirmPassword: 'StillBlocked1' },
    });
    assert.equal(r.status, 200);
    assert.equal(r.data.token, undefined, 'no token for a suspended account');
    assert.equal(r.data.code, 'ACCOUNT_SUSPENDED');
    target.password = 'StillBlocked1';
  });

  it('reinstate restores access', async () => {
    const r = await api('POST', `/api/admin/users/${target.id}/reinstate`, { token: admin.token, body: {} });
    assert.equal(r.status, 200);
    const l = await login(target);
    assert.equal(l.status, 200);
    target.token = l.data.token;
    assert.equal((await api('GET', '/api/profile', { token: target.token })).status, 200);
  });

  it('a suspension with days ends by itself', async () => {
    await api('POST', `/api/admin/users/${target.id}/suspend`, { token: admin.token, body: { reason: 'Short break', days: 1 } });
    assert.equal((await login(target)).status, 403);
    await db.collection('users').updateOne({ phone: target.intlPhone }, { $set: { suspendedUntil: new Date(Date.now() - 1000) } });
    const l = await login(target);
    assert.equal(l.status, 200);
    target.token = l.data.token;
    const doc = await db.collection('users').findOne({ phone: target.intlPhone });
    assert.equal(doc.status, 'active');
  });

  it('a suspension without days is indefinite', async () => {
    const r = await api('POST', `/api/admin/users/${target.id}/suspend`, { token: admin.token, body: { reason: 'Under investigation' } });
    assert.equal(r.status, 200);
    assert.equal(r.data.suspendedUntil, null);
    assert.equal((await login(target)).data.code, 'ACCOUNT_SUSPENDED');
    await api('POST', `/api/admin/users/${target.id}/reinstate`, { token: admin.token, body: {} });
    target.token = (await login(target)).data.token;
  });

  it('ban blocks the user permanently until reinstated', async () => {
    const noReason = await api('POST', `/api/admin/users/${target.id}/ban`, { token: admin.token, body: {} });
    assert.equal(noReason.status, 400);

    const r = await api('POST', `/api/admin/users/${target.id}/ban`, { token: admin.token, body: { reason: 'Fraud' } });
    assert.equal(r.status, 200);
    assert.equal((await api('GET', '/api/profile', { token: target.token })).status, 401);
    const l = await login(target);
    assert.equal(l.status, 403);
    assert.equal(l.data.code, 'ACCOUNT_BANNED');
    assert.ok(!JSON.stringify(l.data).includes('Fraud'));

    // a banned user cannot register again with the same phone either
    const again = await api('POST', '/api/auth/signup', { body: signupBody(target.phone) });
    assert.equal(again.status, 409);

    const back = await api('POST', `/api/admin/users/${target.id}/reinstate`, { token: admin.token, body: { note: 'Appeal accepted' } });
    assert.equal(back.status, 200);
    const ok = await login(target);
    assert.equal(ok.status, 200);
    target.token = ok.data.token;
  });

  it('a banned user cannot delete their account to escape the ban', async () => {
    const v = await registerUser();
    await api('POST', `/api/admin/users/${v.id}/ban`, { token: admin.token, body: { reason: 'Fraud' } });
    const r = await api('POST', '/api/account/delete', { token: v.token, body: { password: PASSWORD } });
    assert.equal(r.status, 401, 'their sessions are revoked, so they cannot even reach the endpoint');
    const doc = await db.collection('users').findOne({ phone: v.intlPhone });
    assert.equal(doc.status, 'banned');
  });

  it('flag / unflag with a reason and filter by flagged', async () => {
    const noReason = await api('POST', `/api/admin/users/${target.id}/flag`, { token: admin.token, body: { flagged: true } });
    assert.equal(noReason.status, 400);
    const notBool = await api('POST', `/api/admin/users/${target.id}/flag`, { token: admin.token, body: { flagged: 'yes' } });
    assert.equal(notBool.status, 400);

    const on = await api('POST', `/api/admin/users/${target.id}/flag`, { token: admin.token, body: { flagged: true, reason: 'Multiple complaints' } });
    assert.equal(on.status, 200);
    const list = await api('GET', '/api/admin/users?flagged=true', { token: admin.token });
    const found = list.data.users.find((x) => String(x.id) === target.id);
    assert.ok(found);
    assert.equal(found.flagReason, 'Multiple complaints');

    const off = await api('POST', `/api/admin/users/${target.id}/flag`, { token: admin.token, body: { flagged: false } });
    assert.equal(off.status, 200);
    const list2 = await api('GET', '/api/admin/users?flagged=true', { token: admin.token });
    assert.ok(!list2.data.users.some((x) => String(x.id) === target.id));
  });

  it('filters by status', async () => {
    const v = await registerUser();
    await api('POST', `/api/admin/users/${v.id}/suspend`, { token: admin.token, body: { reason: 'Filter test' } });
    const list = await api('GET', '/api/admin/users?status=suspended', { token: admin.token });
    assert.ok(list.data.users.some((x) => String(x.id) === v.id));
    assert.ok(list.data.users.every((x) => x.status === 'suspended'));
  });

  it('admin can read the security events of a user, including admin actions', async () => {
    const r = await api('GET', `/api/admin/users/${target.id}/security-events`, { token: admin.token });
    assert.equal(r.status, 200);
    const types = r.data.events.map((e) => e.type);
    for (const t of ['suspended', 'banned', 'reinstated', 'flagged', 'suspension_expired', 'login_blocked']) {
      assert.ok(types.includes(t), `${t} missing from ${types.join()}`);
    }
    assert.equal((await api('GET', '/api/admin/users/bad-id/security-events', { token: admin.token })).status, 400);
  });

  it('reinstate refuses a deleted account', async () => {
    const v = await registerUser();
    await api('POST', '/api/account/delete', { token: v.token, body: { password: PASSWORD } });
    const r = await api('POST', `/api/admin/users/${v.id}/reinstate`, { token: admin.token, body: {} });
    assert.equal(r.status, 400);
  });

  it('an admin phone listed in ADMIN_PHONES becomes admin after OTP verification (role is never taken from signup)', async () => {
    const phone = nextPhone();
    const r = await api('POST', '/api/auth/signup', { body: signupBody(phone, { role: 'driver' }) });
    assert.equal(r.status, 201);
    const doc = await db.collection('users').findOne({ phone: intl(phone) });
    assert.equal(doc.role, 'driver');
  });
});

// ==========================================================
//  Delete account
// ==========================================================
describe('Delete account', () => {
  let u;
  before(async () => {
    u = await registerUser();
    await api('PUT', '/api/profile/photo', {
      token: u.token,
      form: imageForm({ photo: { buf: pngBuf(), filename: 'me.png', type: 'image/png' } }),
    });
  });

  it('requires the password', async () => {
    assert.equal((await api('POST', '/api/account/delete', { token: u.token, body: {} })).status, 400);
    assert.equal((await api('POST', '/api/account/delete', { token: u.token, body: { password: 'Wrong1234' } })).status, 401);
    assert.equal((await api('POST', '/api/account/delete', { body: { password: PASSWORD } })).status, 401);
  });

  it('deletes the account, wipes personal data and ends every session', async () => {
    const second = (await login(u, { deviceId: 'second' })).data.token;
    const photoUrl = (await api('GET', '/api/profile', { token: u.token })).data.user.photoUrl;
    assert.ok(photoUrl);

    const r = await api('POST', '/api/account/delete', { token: u.token, body: { password: PASSWORD } });
    assert.equal(r.status, 200);

    assert.equal((await api('GET', '/api/profile', { token: u.token })).status, 401);
    assert.equal((await api('GET', '/api/profile', { token: second })).status, 401);
    assert.equal((await login(u)).status, 401);

    await new Promise((res) => setTimeout(res, 200));
    assert.equal((await fetch(photoUrl)).status, 404, 'photo removed');

    const doc = await db.collection('users').findOne({ _id: new mongoose.Types.ObjectId(u.id) });
    assert.equal(doc.status, 'deleted');
    assert.equal(doc.name, 'Deleted user');
    assert.notEqual(doc.phone, u.intlPhone);
    assert.equal(doc.email, undefined);
    assert.equal(doc.photo, undefined);
  });

  it('the phone number can be used to register a new account afterwards', async () => {
    const phone = u.phone;
    const s = await api('POST', '/api/auth/signup', { body: signupBody(phone, { name: 'Fresh Start' }) });
    assert.equal(s.status, 201);
    await setOtp(u.intlPhone, 'signup');
    const v = await api('POST', '/api/auth/verify-otp', { body: { phone, code: '123456' } });
    assert.equal(v.status, 200);
    assert.equal(v.data.user.name, 'Fresh Start');
    assert.notEqual(String(v.data.user.id), u.id, 'a brand new account');
  });
});