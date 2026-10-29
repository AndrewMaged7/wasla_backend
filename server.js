require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

// ---------------------- Config ----------------------
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/auth_demo';
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
// لو true: ممنوع تسجيل الدخول قبل تفعيل الايميل
const REQUIRE_EMAIL_VERIFICATION = process.env.REQUIRE_EMAIL_VERIFICATION === 'true';

if (!JWT_SECRET) {
  console.error('❌ لازم تضيف JWT_SECRET في ملف .env');
  process.exit(1);
}

// ---------------------- User Model ----------------------
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: [true, 'الاسم مطلوب'], trim: true, minlength: 2, maxlength: 50 },
    email: { type: String, required: [true, 'الايميل مطلوب'], unique: true, lowercase: true, trim: true },
    password: { type: String, required: true, select: false },
    isVerified: { type: Boolean, default: false },
    verificationToken: { type: String, select: false },
    verificationExpires: { type: Date, select: false },
    passwordResetToken: { type: String, select: false },
    passwordResetExpires: { type: Date, select: false },
    passwordChangedAt: { type: Date },
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);

// ---------------------- Helpers ----------------------
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,64}$/;

function signToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function validateSignup({ name, email, password, confirmPassword }) {
  const errors = [];
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 50) {
    errors.push('الاسم لازم يكون من 2 لـ 50 حرف');
  }
  if (typeof email !== 'string' || !EMAIL_REGEX.test(email.trim())) {
    errors.push('الايميل غير صالح');
  }
  if (typeof password !== 'string' || !PASSWORD_REGEX.test(password)) {
    errors.push('الباسورد لازم يكون 8 حروف على الأقل ويحتوي على حرف كبير وحرف صغير ورقم');
  }
  if (confirmPassword !== undefined && password !== confirmPassword) {
    errors.push('الباسورد وتأكيده مش متطابقين');
  }
  return errors;
}

// إرسال ايميل التفعيل (لو SMTP مش متظبط بيطبع اللينك في الـ console)
async function sendVerificationEmail(email, name, token) {
  const link = `${BASE_URL}/api/auth/verify-email/${token}`;

  if (!process.env.SMTP_HOST) {
    console.log(`📧 [DEV] لينك تفعيل ${email}: ${link}`);
    return;
  }

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });

  await transporter.sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: email,
    subject: 'فعّل حسابك',
    html: `
      <div dir="rtl" style="font-family:Arial,sans-serif">
        <h2>أهلاً ${name} 👋</h2>
        <p>اضغط على الزر ده لتفعيل حسابك (اللينك صالح لمدة 24 ساعة):</p>
        <p><a href="${link}" style="background:#4f46e5;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none">تفعيل الحساب</a></p>
        <p>لو الزر مش شغال انسخ اللينك ده: <br>${link}</p>
      </div>`,
  });
}

// هاش وهمي بنقارن عليه لو الايميل مش موجود (علشان وقت الرد يفضل ثابت تقريباً)
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 12);

// إرسال ايميل استرجاع الباسورد (لو SMTP مش متظبط بيطبع التوكن في الـ console)
async function sendPasswordResetEmail(email, name, token) {
  const link = `${FRONTEND_URL}/reset-password/${token}`;

  if (!process.env.SMTP_HOST) {
    console.log(`📧 [DEV] استرجاع باسورد ${email}`);
    console.log(`   اللينك: ${link}`);
    console.log(`   التوكن (استخدمه في POST /api/auth/reset-password/<token>): ${token}`);
    return;
  }

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });

  await transporter.sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: email,
    subject: 'استرجاع كلمة المرور',
    html: `
      <div dir="rtl" style="font-family:Arial,sans-serif">
        <h2>أهلاً ${name}</h2>
        <p>وصلنا طلب لاسترجاع كلمة المرور. اللينك صالح لمدة 15 دقيقة:</p>
        <p><a href="${link}" style="background:#4f46e5;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none">تغيير كلمة المرور</a></p>
        <p>لو الزر مش شغال انسخ اللينك ده: <br>${link}</p>
        <p>لو انت مطلبتش ده تجاهل الرسالة وحسابك آمن.</p>
      </div>`,
  });
}

// ---------------------- App ----------------------
const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10kb' }));

const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'محاولات كتير، جرب تاني بعد شوية' },
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'محاولات تسجيل دخول كتير، جرب تاني بعد 15 دقيقة' },
});

const forgotLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'طلبات كتير، جرب تاني بعد ساعة' },
});

// ---------------------- Routes ----------------------

// POST /api/auth/signup
app.post('/api/auth/signup', signupLimiter, async (req, res, next) => {
  try {
    const { name, email, password, confirmPassword } = req.body || {};

    const errors = validateSignup({ name, email, password, confirmPassword });
    if (errors.length) {
      return res.status(400).json({ success: false, message: 'بيانات غير صحيحة', errors });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) {
      return res.status(409).json({ success: false, message: 'الايميل ده مسجل بالفعل' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const rawVerificationToken = crypto.randomBytes(32).toString('hex');

    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      password: hashedPassword,
      verificationToken: sha256(rawVerificationToken),
      verificationExpires: Date.now() + 24 * 60 * 60 * 1000,
    });

    try {
      await sendVerificationEmail(user.email, user.name, rawVerificationToken);
    } catch (mailErr) {
      console.error('⚠️ فشل إرسال ايميل التفعيل:', mailErr.message);
    }

    const token = signToken(user._id);

    return res.status(201).json({
      success: true,
      message: 'تم إنشاء الحساب بنجاح، راجع ايميلك لتفعيل الحساب',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        isVerified: user.isVerified,
        createdAt: user.createdAt,
      },
    });
  } catch (err) {
    if (err && err.code === 11000) {
      return res.status(409).json({ success: false, message: 'الايميل ده مسجل بالفعل' });
    }
    next(err);
  }
});

// GET /api/auth/verify-email/:token
app.get('/api/auth/verify-email/:token', async (req, res, next) => {
  try {
    const hashed = sha256(req.params.token);

    const user = await User.findOne({
      verificationToken: hashed,
      verificationExpires: { $gt: Date.now() },
    }).select('+verificationToken +verificationExpires');

    if (!user) {
      return res.status(400).json({ success: false, message: 'لينك التفعيل غير صالح أو منتهي' });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    await user.save();

    return res.json({ success: true, message: 'تم تفعيل الحساب بنجاح ✅' });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/login
app.post('/api/auth/login', loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (typeof email !== 'string' || typeof password !== 'string' || !email || !password) {
      return res.status(400).json({ success: false, message: 'الايميل والباسورد مطلوبين' });
    }

    const user = await User.findOne({ email: email.trim().toLowerCase() }).select('+password');

    // بنقارن دايماً (حتى لو المستخدم مش موجود) وبنرجع نفس الرسالة في الحالتين
    const isMatch = await bcrypt.compare(password, user ? user.password : DUMMY_HASH);

    if (!user || !isMatch) {
      return res.status(401).json({ success: false, message: 'الايميل أو الباسورد غلط' });
    }

    if (REQUIRE_EMAIL_VERIFICATION && !user.isVerified) {
      return res.status(403).json({ success: false, message: 'لازم تفعّل ايميلك الأول' });
    }

    const token = signToken(user._id);

    return res.json({
      success: true,
      message: 'تم تسجيل الدخول بنجاح',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        isVerified: user.isVerified,
      },
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', forgotLimiter, async (req, res, next) => {
  // نفس الرد دايماً علشان محدش يعرف مين مسجل ومين لأ
  const genericResponse = {
    success: true,
    message: 'لو الايميل ده مسجل عندنا، هيوصلك لينك لاسترجاع كلمة المرور',
  };

  try {
    const { email } = req.body || {};

    if (typeof email !== 'string' || !EMAIL_REGEX.test(email.trim())) {
      return res.status(400).json({ success: false, message: 'الايميل غير صالح' });
    }

    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user) {
      return res.json(genericResponse);
    }

    const rawToken = crypto.randomBytes(32).toString('hex');
    user.passwordResetToken = sha256(rawToken);
    user.passwordResetExpires = Date.now() + 15 * 60 * 1000; // 15 دقيقة
    await user.save();

    try {
      await sendPasswordResetEmail(user.email, user.name, rawToken);
    } catch (mailErr) {
      console.error('⚠️ فشل إرسال ايميل الاسترجاع:', mailErr.message);
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();
    }

    return res.json(genericResponse);
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/reset-password/:token
app.post('/api/auth/reset-password/:token', async (req, res, next) => {
  try {
    const { password, confirmPassword } = req.body || {};

    if (typeof password !== 'string' || !PASSWORD_REGEX.test(password)) {
      return res.status(400).json({
        success: false,
        message: 'الباسورد لازم يكون 8 حروف على الأقل ويحتوي على حرف كبير وحرف صغير ورقم',
      });
    }
    if (confirmPassword !== undefined && password !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'الباسورد وتأكيده مش متطابقين' });
    }

    const user = await User.findOne({
      passwordResetToken: sha256(req.params.token),
      passwordResetExpires: { $gt: Date.now() },
    }).select('+passwordResetToken +passwordResetExpires +password');

    if (!user) {
      return res.status(400).json({ success: false, message: 'اللينك غير صالح أو منتهي' });
    }

    user.password = await bcrypt.hash(password, 12);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    // أي توكن اتعمل قبل كده يبقى باطل
    user.passwordChangedAt = new Date(Date.now() - 1000);
    await user.save();

    const token = signToken(user._id);

    return res.json({
      success: true,
      message: 'تم تغيير كلمة المرور بنجاح',
      token,
    });
  } catch (err) {
    next(err);
  }
});

// Middleware لحماية الراوتس
async function protect(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.split(' ')[1] : null;
    if (!token) {
      return res.status(401).json({ success: false, message: 'مطلوب تسجيل دخول' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ success: false, message: 'المستخدم غير موجود' });
    }

    // لو الباسورد اتغير بعد إصدار التوكن، التوكن القديم يبقى باطل
    if (
      user.passwordChangedAt &&
      decoded.iat < Math.floor(user.passwordChangedAt.getTime() / 1000)
    ) {
      return res.status(401).json({ success: false, message: 'الباسورد اتغير، سجل دخول تاني' });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'توكن غير صالح أو منتهي' });
  }
}

// GET /api/auth/me
app.get('/api/auth/me', protect, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      isVerified: req.user.isVerified,
    },
  });
});

app.get('/', (req, res) => res.json({ success: true, message: 'API شغال 🚀' }));

app.use((req, res) => {
  res.status(404).json({ success: false, message: 'المسار غير موجود' });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('❌ Error:', err);
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, message: 'JSON غير صالح' });
  }
  res.status(500).json({ success: false, message: 'حصل خطأ في السيرفر' });
});

// ---------------------- Start ----------------------
mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log('✅ متصل بـ MongoDB');
    app.listen(PORT, () => console.log(`🚀 السيرفر شغال على ${BASE_URL}`));
  })
  .catch((err) => {
    console.error('❌ فشل الاتصال بـ MongoDB:', err.message);
    process.exit(1);
  });