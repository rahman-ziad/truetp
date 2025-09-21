require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const pino = require('pino');
const app = express();
const logger = pino({ level: process.env.LOG_LEVEL || 'info' });

// Security & parsing middleware
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({
  origin: '*', // TODO: restrict in production
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '10kb' }));

// Basic IP rate limiter (global)
const globalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
  max: parseInt(process.env.RATE_LIMIT_MAX || '120', 10),
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// Initialize Firebase Admin SDK with flexible credential loading
function loadFirebaseCredentials() {
  try {
  const credentials = JSON.parse(process.env.FIREBASE_CREDENTIALS);
  admin.initializeApp({
    credential: admin.credential.cert(credentials),
  });
} catch (error) {
  console.error('Error initializing Firebase:', error.message, error.stack);
  process.exit(1);
}}
loadFirebaseCredentials();

// MiMSMS configuration
const SMS_API_URL = 'https://api.mimsms.com/api/SmsSending/SMS';
const SMS_USERNAME = process.env.SMS_USERNAME || 'fahimmaruf@gmail.com';
const SMS_API_KEY = process.env.SMS_API_KEY || 'VAUSWN3QKZ7FQ0H';
const SMS_SENDER_NAME = process.env.SMS_SENDER_NAME || '8809601003504';
const SMS_TRANSACTION_TYPE = 'T';

// JWT / security configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'your_refresh_token_secret_key';
const HASH_SALT_ROUNDS = parseInt(process.env.HASH_SALT_ROUNDS || '10', 10);
const OTP_TTL_MS = parseInt(process.env.OTP_TTL_MS || (5 * 60 * 1000).toString(), 10);
const OTP_MAX_ATTEMPTS = parseInt(process.env.OTP_MAX_ATTEMPTS || '5', 10);
const PHONE_OTP_WINDOW_MS = parseInt(process.env.PHONE_OTP_WINDOW_MS || '60000', 10);
const PHONE_OTP_MAX_PER_WINDOW = parseInt(process.env.PHONE_OTP_MAX_PER_WINDOW || '3', 10);

// Firestore collection
const db = admin.firestore();
const otpCollection = db.collection('truetag_otps');
const tokenCollection = db.collection('truetag_tokens');

// Helpers
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Validate phone number format
function validatePhoneNumber(phoneNumber) {
  const phoneRegex = /^\+?[1-9]\d{1,14}$/;
  return phoneRegex.test(phoneNumber);
}

// Normalize phone number (remove + prefix if present)
function normalizePhoneNumber(phoneNumber) {
  return phoneNumber.startsWith('+') ? phoneNumber.substring(1) : phoneNumber;
}

// Opportunistic cleanup of expired OTPs (fire-and-forget)
async function cleanupExpiredOtps(limit = 25) {
  try {
    const now = Date.now();
    const snap = await otpCollection.where('expiresAt', '<', now).limit(limit).get();
    if (!snap.empty) {
      const batch = db.batch();
      snap.docs.forEach(doc => batch.delete(doc.ref));
      await batch.commit();
      logger.debug({ count: snap.size }, 'Cleaned expired OTP docs');
    }
  } catch (e) {
    logger.warn({ err: e }, 'Expired OTP cleanup failed');
  }
}

// Simple per-phone in-memory tracker (stateless fallback) – for multi-instance, consider Firestore doc counters
const phoneRequestCache = new Map(); // phone -> { windowStart, count }
function allowPhoneOtpRequest(phoneNumber) {
  const now = Date.now();
  const rec = phoneRequestCache.get(phoneNumber);
  if (!rec || now - rec.windowStart > PHONE_OTP_WINDOW_MS) {
    phoneRequestCache.set(phoneNumber, { windowStart: now, count: 1 });
    return true;
  }
  if (rec.count >= PHONE_OTP_MAX_PER_WINDOW) return false;
  rec.count += 1;
  return true;
}

// Send OTP endpoint
app.post('/api/truetag/send-otp', async (req, res) => {
  const { phoneNumber } = req.body;

  if (!phoneNumber) {
    return res.status(400).json({ error: 'Phone number required' });
  }

  if (!validatePhoneNumber(phoneNumber)) {
    return res.status(400).json({ error: 'Invalid phone number format' });
  }

  if (!allowPhoneOtpRequest(phoneNumber)) {
    return res.status(429).json({ error: 'Too many OTP requests. Please wait and try again.' });
  }

  const normalizedPhoneNumber = normalizePhoneNumber(phoneNumber);
  const otp = generateOTP();
  const sessionId = uuidv4();
  const expiresAt = Date.now() + OTP_TTL_MS;

  try {
    await otpCollection.doc(sessionId).set({
      phoneNumber,
      otp,
      expiresAt,
      createdAt: Date.now(),
      attempts: 0,
      locked: false,
    });

    cleanupExpiredOtps().catch(() => {});

    const response = await fetch(SMS_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        UserName: SMS_USERNAME,
        Apikey: SMS_API_KEY,
        MobileNumber: normalizedPhoneNumber,
        CampaignId: 'null',
        SenderName: SMS_SENDER_NAME,
        TransactionType: SMS_TRANSACTION_TYPE,
  Message: `welcome to RR Kabel. your otp is ${otp}`,
      }),
    });

    const result = await response.json();
    if (!response.ok || result.statusCode !== '200') {
      return res.status(500).json({ error: `Failed to send OTP: ${result.responseResult || result.message || 'SMS service unavailable'}` });
    }

    res.status(200).json({ sessionId, expiresInMs: OTP_TTL_MS });
  } catch (error) {
    logger.error({ err: error }, 'Send OTP failure');
    res.status(500).json({ error: `Failed to send OTP: ${error.message}` });
  }
});

// Verify OTP and login endpoint
app.post('/api/truetag/verify-otp', async (req, res) => {
  const { phoneNumber, otp, sessionId } = req.body;

  if (!phoneNumber || !otp || !sessionId) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const otpDoc = await otpCollection.doc(sessionId).get();
    if (!otpDoc.exists) {
      return res.status(400).json({ error: 'Invalid session ID' });
    }

    const data = otpDoc.data();
    if (data.locked) {
      return res.status(400).json({ error: 'OTP locked due to too many attempts' });
    }
    if (Date.now() > data.expiresAt) {
      await otpCollection.doc(sessionId).delete();
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
    if (data.phoneNumber !== phoneNumber || data.otp !== otp) {
      const newAttempts = (data.attempts || 0) + 1;
      const locked = newAttempts >= OTP_MAX_ATTEMPTS;
      await otpCollection.doc(sessionId).update({ attempts: newAttempts, locked });
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // success
    await otpCollection.doc(sessionId).delete();
    cleanupExpiredOtps().catch(() => {});

    const jwtPayload = { phoneNumber };
    const token = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: '30d' });
    const refreshToken = jwt.sign(jwtPayload, REFRESH_TOKEN_SECRET, { expiresIn: '90d' });

    // Hash tokens before storing
    const tokenHash = await bcrypt.hash(token, HASH_SALT_ROUNDS);
    const refreshTokenHash = await bcrypt.hash(refreshToken, HASH_SALT_ROUNDS);

    await tokenCollection.doc(phoneNumber).set({
      tokenHash,
      refreshTokenHash,
      createdAt: Date.now(),
    });

    // Ensure user profile exists (minimal fields)
  const userQuery = await db.collection('truetag_users')
      .where('phone_number', '==', phoneNumber)
      .limit(1)
      .get();

    let profile;
    if (userQuery.empty) {
  const docRef = await db.collection('truetag_users').add({
        phone_number: phoneNumber,
        name: '',
        email: '',
        image_url: '',
        address: '',
        created_at: Date.now(),
      });
      profile = { name: '', email: '', image_url: '', address: '' };
    } else {
      const userData = userQuery.docs[0].data();
      profile = { name: userData.name || '', email: userData.email || '', image_url: userData.image_url || '', address: userData.address || '' };
    }

  logger.info({ phoneNumber }, 'OTP verified, tokens issued (truetag)');
    res.status(200).json({ jwt: token, refreshToken, profile });
  } catch (error) {
    logger.error({ err: error }, 'Verify OTP failure');
    res.status(500).json({ error: `OTP verification failed: ${error.message}` });
  }
});

// Auth middleware verifying JWT AND hashed token presence
async function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return res.status(401).json({ error: 'Missing or invalid Authorization header' });
    }
    const token = parts[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const tokenDoc = await tokenCollection.doc(decoded.phoneNumber).get();
    if (!tokenDoc.exists) return res.status(401).json({ error: 'Token revoked' });
    const { tokenHash } = tokenDoc.data();
    const ok = await bcrypt.compare(token, tokenHash);
    if (!ok) return res.status(401).json({ error: 'Token invalid' });
    req.user = { phoneNumber: decoded.phoneNumber };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// Protected profile endpoint
app.get('/api/truetag/profile', authMiddleware, async (req, res) => {
  try {
    const phoneNumber = req.user.phoneNumber;
  const userSnap = await db.collection('truetag_users').where('phone_number', '==', phoneNumber).limit(1).get();
    if (userSnap.empty) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    const doc = userSnap.docs[0];
    const data = doc.data();
    res.status(200).json({ profile: { name: data.name || '', email: data.email || '', image_url: data.image_url || '', address: data.address || '' } });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Refresh token endpoint
app.post('/api/truetag/refresh-token', async (req, res) => {
  const { refreshToken, phoneNumber } = req.body;

  if (!refreshToken || !phoneNumber) {
    return res.status(400).json({ error: 'Refresh token and phone number required' });
  }

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    if (decoded.phoneNumber !== phoneNumber) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const tokenDoc = await tokenCollection.doc(phoneNumber).get();
    if (!tokenDoc.exists) {
      return res.status(401).json({ error: 'Refresh token not found' });
    }

    const { refreshTokenHash } = tokenDoc.data();
    const isMatch = await bcrypt.compare(refreshToken, refreshTokenHash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const newToken = jwt.sign({ phoneNumber }, JWT_SECRET, { expiresIn: '30d' });
    const newTokenHash = await bcrypt.hash(newToken, HASH_SALT_ROUNDS);
    await tokenCollection.doc(phoneNumber).update({ tokenHash: newTokenHash });

    res.status(200).json({ jwt: newToken });
  } catch (error) {
    res.status(401).json({ error: `Invalid or expired refresh token: ${error.message}` });
  }
});
// Update profile endpoint
app.post('/api/truetag/profile', authMiddleware, async (req, res) => {
  const { name, email, address, image_url } = req.body;
  const phoneNumber = req.user.phoneNumber;

  if (!name && !email && !address && !image_url) {
    return res.status(400).json({ error: 'At least one field (name, email, address, image_url) is required' });
  }

  try {
    const userQuery = await db.collection('truetag_users')
      .where('phone_number', '==', phoneNumber)
      .limit(1)
      .get();

    if (userQuery.empty) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userDoc = userQuery.docs[0];
    const updateData = {
      updated_at: Date.now(),
    };
    if (name) updateData.name = name;
    if (email) updateData.email = email;
    if (address) updateData.address = address;
    if (image_url) updateData.image_url = image_url;

    await userDoc.ref.update(updateData);

    logger.info({ phoneNumber }, 'Profile updated');
    res.status(200).json({ message: 'Profile updated successfully' });
  } catch (error) {
    logger.error({ err: error }, 'Profile update failure');
    res.status(500).json({ error: `Failed to update profile: ${error.message}` });
  }
});
// Logout endpoint
app.post('/api/truetag/logout', async (req, res) => {
  const { phoneNumber } = req.body;

  if (!phoneNumber) {
    return res.status(400).json({ error: 'Phone number is required' });
  }

  try {
    const tokenDoc = await tokenCollection.doc(phoneNumber).get();
    if (tokenDoc.exists) {
      await tokenCollection.doc(phoneNumber).delete();
    }
    res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: `Failed to log out: ${error.message}` });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error({ err }, 'Unhandled error');
  res.status(500).json({ error: `Internal server error: ${err.message}` });
});

// Health check endpoint
app.get('/truetag/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Truetag server running on port ${PORT}`);
});
