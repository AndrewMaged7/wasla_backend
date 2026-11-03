const nodemailer = require('nodemailer');
const env = require('../config/env');

async function sendSms(phone, text) {
  const sid = env.TWILIO_ACCOUNT_SID;
  const authToken = env.TWILIO_AUTH_TOKEN;
  const from = env.TWILIO_FROM;

  if (sid && authToken && from) {
    const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
      method: 'POST',
      headers: {
        Authorization: 'Basic ' + Buffer.from(`${sid}:${authToken}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ To: phone, From: from, Body: text }),
    });
    if (!res.ok) throw new Error(`SMS provider error ${res.status}: ${await res.text()}`);
    return;
  }

  if (env.IS_PRODUCTION) throw new Error('SMS provider is not configured');
  console.log(`[DEV] SMS to ${phone}: ${text}`);
}

async function sendEmail(to, subject, text) {
  if (!env.SMTP_HOST) {
    if (env.IS_PRODUCTION) throw new Error('SMTP is not configured');
    console.log(`[DEV] Email to ${to} | ${subject}: ${text}`);
    return;
  }

  const transporter = nodemailer.createTransport({
    host: env.SMTP_HOST,
    port: env.SMTP_PORT,
    secure: env.SMTP_PORT === 465,
    auth: { user: env.SMTP_USER, pass: env.SMTP_PASS },
  });

  await transporter.sendMail({
    from: env.MAIL_FROM || env.SMTP_USER,
    to,
    subject,
    text,
  });
}

module.exports = { sendSms, sendEmail };