// Updated backend with 2‑step verification (email OTP), Google reCAPTCHA, and additional security middleware
// -------------------------------------------------------------
// Requirements added: helmet, express-rate-limit, express-validator, axios
// Make sure to run: npm i helmet express-rate-limit express-validator axios bcryptjs

const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const axios = require('axios');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();

// ----------- Global middleware -----------
app.use(bodyParser.json());
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || true }));
app.use(helmet()); // sets secure HTTP headers

// Basic rate‑limiter (100 req / 15 min per IP)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// ----------- MySQL pool -----------
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ----------- Nodemailer -----------
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ----------- Utilities -----------
const verificationTokens = new Map(); // email‑link verification (existing)
const otpStore = new Map();           // 2FA OTP codes { email → { code, exp } }

function generateRandomToken(len = 32) {
  return [...Array(len)].map(() => Math.floor(Math.random() * 36).toString(36)).join('');
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Verify Google reCAPTCHA v2 / v3 token
async function verifyCaptcha(req, res, next) {
  try {
    const { captchaToken } = req.body;
    if (!captchaToken) return res.status(400).json({ message: 'Captcha token missing' });

    const { data } = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
      params: {
        secret: process.env.RECAPTCHA_SECRET,
        response: captchaToken,
        remoteip: req.ip
      }
    });

    if (!data.success || (data.score !== undefined && data.score < 0.5)) {
      return res.status(400).json({ message: 'Captcha validation failed' });
    }

    next();
  } catch (err) {
    console.error('🛑 reCAPTCHA error:', err.message);
    return res.status(500).json({ message: 'Captcha verification error' });
  }
}

// ----------- Auth: register & login with 2‑step verification -----------
// (Very lightweight example — extend/replace with your existing auth logic.)

// Register new user
app.post('/api/register', verifyCaptcha, [
  body('email').isEmail(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.query('INSERT INTO users (email, password_hash) VALUES (?, ?) ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)', [email, hash], (err) => {
    if (err) {
      console.error('🛑 DB error during register:', err);
      return res.status(500).json({ message: 'Database error' });
    }
    res.json({ message: 'User registered' });
  });
});

// Step 1: verify credentials and send OTP
app.post('/api/login', verifyCaptcha, [
  body('email').isEmail(),
  body('password').isLength({ min: 6 })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;
  db.query('SELECT password_hash FROM users WHERE email = ?', [email], async (err, rows) => {
    if (err) {
      console.error('🛑 DB error during login:', err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (rows.length === 0 || !await bcrypt.compare(password, rows[0].password_hash)) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const otp = generateOTP();
    otpStore.set(email, { code: otp, exp: Date.now() + 10 * 60 * 1000 }); // 10‑min expiry
    transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP code',
      text: `Your one‑time login code is ${otp}. It will expire in 10 minutes.`
    }, (emailErr) => {
      if (emailErr) {
        console.error('📧 OTP send error:', emailErr);
        return res.status(500).json({ message: 'Failed to send OTP' });
      }
      res.json({ message: 'OTP sent' });
    });
  });
});

// Step 2: verify OTP
app.post('/api/verify‑otp', verifyCaptcha, [
  body('email').isEmail(),
  body('code').isLength({ min: 6, max: 6 })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, code } = req.body;
  const entry = otpStore.get(email);
  if (!entry || entry.code !== code || Date.now() > entry.exp) {
    return res.status(400).json({ message: 'OTP invalid or expired' });
  }
  otpStore.delete(email);
  // TODO: issue JWT / session cookie here
  res.json({ message: 'Login successful' });
});

// ----------- Existing endpoints (now protected by captcha + validation) -----------
app.post('/api/found', verifyCaptcha, [
  body('email').isEmail(),
  body('item_name').notEmpty().trim().escape(),
  body('color').notEmpty().trim().escape(),
  body('brand').optional().trim().escape(),
  body('location').notEmpty().trim().escape()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, item_name, color, brand, location } = req.body;
  const sql = 'INSERT INTO found_items (email, item_name, color, brand, location, verified, claimed, claimed_by) VALUES (?, ?, ?, ?, ?, 0, 0, NULL)';
  db.query(sql, [email, item_name, color, brand, location], (err, result) => {
    if (err) {
      console.error('🛑 DB insert error:', err);
      return res.status(500).json({ message: 'Database error' });
    }

    const token = generateRandomToken();
    verificationTokens.set(token, { id: result.insertId, type: 'found' });
    const verifyLink = `https://${process.env.BASE_URL}/api/verify/${token}`;

    transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify your found item',
      html: `<p>Please verify your item by clicking <a href="${verifyLink}">here</a>.</p>`
    }, (emailErr) => {
      if (emailErr) {
        console.error('📧 Email send error:', emailErr);
        return res.status(500).json({ message: 'Verification email failed' });
      }
      res.json({ message: 'Item registered. Check your email to verify.' });
    });
  });
});

app.get('/api/verify/:token', (req, res) => {
  const data = verificationTokens.get(req.params.token);
  if (!data) return res.status(400).send('Token invalid or expired');
  verificationTokens.delete(req.params.token);

  const table = data.type === 'found' ? 'found_items' : 'lost_items';
  db.query(`UPDATE ${table} SET verified = 1 WHERE id = ?`, [data.id], (err) => {
    if (err) {
      console.error('🛑 DB error during verification:', err);
      return res.status(500).send('Database error');
    }
    res.send('Email verified ✔️');
  });
});

app.post('/api/search', verifyCaptcha, [
  body('item_name').notEmpty().trim().escape(),
  body('color').optional().trim().escape(),
  body('brand').optional().trim().escape()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  let { item_name, color, brand } = req.body;
  item_name = item_name.toLowerCase();
  color = color?.toLowerCase();
  brand = brand?.toLowerCase();

  db.query('SELECT * FROM found_items WHERE verified = 1 AND claimed = 0', (err, results) => {
    if (err) {
      console.error('🛑 DB error during search:', err);
      return res.status(500).json({ message: 'Database error' });
    }
    const filtered = results.filter(item => {
      const nm = (item.item_name || '').toLowerCase();
      const clr = (item.color || '').toLowerCase();
      const br = (item.brand || '').toLowerCase();
      return nm.includes(item_name) && (!color || clr.includes(color)) && (!brand || br.includes(brand));
    });
    res.json(filtered);
  });
});

app.post('/api/claim/:id', verifyCaptcha, [
  body('email').isEmail()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { id } = req.params;
  const { email } = req.body;
  db.query('UPDATE found_items SET claimed = 1, claimed_by = ? WHERE id = ? AND claimed = 0', [email, id], (err, result) => {
    if (err) {
      console.error('🛑 Claim update error:', err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Item not found or already claimed' });
    res.json({ message: 'Item claimed' });
  });
});

// ----------- Server -----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Secure server running on ${PORT}`));
