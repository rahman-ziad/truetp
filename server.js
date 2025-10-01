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
  origin: process.env.CORS_ORIGIN || 'https://your-flutter-app-domain.com', // Restrict to app domain
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '10kb' }));

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
  max: parseInt(process.env.RATE_LIMIT_MAX || '120', 10),
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// Endpoint-specific rate limiter for OTP endpoints
const otpLimiter = rateLimit({
  windowMs: parseInt(process.env.PHONE_OTP_WINDOW_MS || '60000', 10),
  max: parseInt(process.env.PHONE_OTP_MAX_PER_WINDOW || '3', 10),
  keyGenerator: (req) => req.body.phoneNumber || req.ip,
  standardHeaders: true,
  legacyHeaders: false,
});

// Initialize Firebase Admin SDK
function loadFirebaseCredentials() {
  try {
    const credentials = JSON.parse(process.env.FIREBASE_CREDENTIALS);
    admin.initializeApp({
      credential: admin.credential.cert(credentials),
    });
  } catch (error) {
    console.error('Error initializing Firebase:', error.message, error.stack);
    process.exit(1);
  }
}
loadFirebaseCredentials();

// Firestore collections
const db = admin.firestore();
const otpCollection = db.collection('truetag_otps');
const tokenCollection = db.collection('truetag_tokens');
const userCollection = db.collection('truetag_users');

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

// Helpers
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function validatePhoneNumber(phoneNumber) {
  const phoneRegex = /^\+?[1-9]\d{1,14}$/;
  return phoneRegex.test(phoneNumber);
}

function normalizePhoneNumber(phoneNumber) {
  return phoneNumber.startsWith('+') ? phoneNumber.substring(1) : phoneNumber;
}

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

// Send OTP endpoint
app.post('/api/truetag/send-otp', otpLimiter, async (req, res) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) {
    return res.status(400).json({ error: 'Phone number required' });
  }
  if (!validatePhoneNumber(phoneNumber)) {
    return res.status(400).json({ error: 'Invalid phone number format' });
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
        Message: `Welcome to RR Kabel. Your OTP is ${otp}`,
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
app.post('/api/truetag/verify-otp', otpLimiter, async (req, res) => {
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
    // OTP verified, delete OTP doc
    await otpCollection.doc(sessionId).delete();
    cleanupExpiredOtps().catch(() => {});
    // Generate JWT and refresh token
    const jwtPayload = { phoneNumber };
    const token = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: '30d' });
    const refreshToken = jwt.sign(jwtPayload, REFRESH_TOKEN_SECRET, { expiresIn: '90d' });
    // Hash tokens before storing
    const tokenHash = await bcrypt.hash(token, HASH_SALT_ROUNDS);
    const refreshTokenHash = await bcrypt.hash(refreshToken, HASH_SALT_ROUNDS);
    // Store tokens with normalized phone as ID
    const normalizedPhone = normalizePhoneNumber(phoneNumber);
    await tokenCollection.doc(normalizedPhone).set({
      tokenHash,
      refreshTokenHash,
      createdAt: Date.now(),
    });
    // Ensure user profile exists with normalized phone as ID
    const userDocRef = userCollection.doc(normalizedPhone);
    const userDoc = await userDocRef.get();
    if (!userDoc.exists) {
      await userDocRef.set({
        phone_number: phoneNumber,
        name: '',
        email: '',
        image_url: '',
        address: '',
        created_at: Date.now(),
      });
    }
    // Create or update Firebase Auth user
    await admin.auth().getUser(normalizedPhone).catch(async (error) => {
      if (error.code === 'auth/user-not-found') {
        await admin.auth().createUser({ uid: normalizedPhone });
      } else {
        throw error;
      }
    });
    // Generate Firebase custom token
    const firebaseToken = await admin.auth().createCustomToken(normalizedPhone);
    logger.info({ phoneNumber }, 'OTP verified, tokens issued');
    res.status(200).json({ jwt: token, refreshToken, firebaseToken, profile: { name: '', email: '', image_url: '', address: '' } });
  } catch (error) {
    logger.error({ err: error }, 'Verify OTP failure');
    res.status(500).json({ error: `OTP verification failed: ${error.message}` });
  }
});

// Firebase custom token endpoint
app.post('/api/truetag/firebase-token', async (req, res) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) {
    return res.status(400).json({ error: 'Phone number required' });
  }
  if (!validatePhoneNumber(phoneNumber)) {
    return res.status(400).json({ error: 'Invalid phone number format' });
  }
  try {
    const normalizedPhoneNumber = normalizePhoneNumber(phoneNumber);
    const uid = normalizedPhoneNumber;
    // Ensure user exists in Firebase Auth
    await admin.auth().getUser(uid).catch(async (error) => {
      if (error.code === 'auth/user-not-found') {
        await admin.auth().createUser({ uid });
      } else {
        throw error;
      }
    });
    // Generate custom token
    const firebaseToken = await admin.auth().createCustomToken(uid);
    logger.info({ phoneNumber }, 'Firebase custom token generated');
    res.status(200).json({ token: firebaseToken });
  } catch (error) {
    logger.error({ err: error }, 'Firebase token generation failure');
    res.status(500).json({ error: `Failed to generate Firebase token: ${error.message}` });
  }
});

// Auth middleware
async function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return res.status(401).json({ error: 'Missing or invalid Authorization header' });
    }
    const token = parts[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const normalizedPhone = normalizePhoneNumber(decoded.phoneNumber);
    const tokenDoc = await tokenCollection.doc(normalizedPhone).get();
    if (!tokenDoc.exists) return res.status(401).json({ error: 'Token revoked' });
    const { tokenHash } = tokenDoc.data();
    const ok = await bcrypt.compare(token, tokenHash);
    if (!ok) return res.status(401).json({ error: 'Token invalid' });
    req.user = { phoneNumber: decoded.phoneNumber };
    next();
  } catch (e) {
    logger.error({ err: e }, 'Auth middleware failure');
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// Protected profile endpoint
app.get('/api/truetag/profile', authMiddleware, async (req, res) => {
  try {
    const phoneNumber = req.user.phoneNumber;
    const normalizedPhone = normalizePhoneNumber(phoneNumber);
    const userDoc = await userCollection.doc(normalizedPhone).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    const data = userDoc.data();
    res.status(200).json({
      profile: {
        name: data.name || '',
        email: data.email || '',
        image_url: data.image_url || '',
        address: data.address || '',
        phone_number: data.phone_number || '',
      }
    });
  } catch (e) {
    logger.error({ err: e }, 'Profile fetch failure');
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
    const normalizedPhone = normalizePhoneNumber(phoneNumber);
    const tokenDoc = await tokenCollection.doc(normalizedPhone).get();
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
    await tokenCollection.doc(normalizedPhone).update({ tokenHash: newTokenHash });
    res.status(200).json({ jwt: newToken });
  } catch (error) {
    logger.error({ err: error }, 'Refresh token failure');
    res.status(401).json({ error: `Invalid or expired refresh token: ${error.message}` });
  }
});

// Logout endpoint
app.post('/api/truetag/logout', async (req, res) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) {
    return res.status(400).json({ error: 'Phone number is required' });
  }
  try {
    const normalizedPhone = normalizePhoneNumber(phoneNumber);
    const tokenDoc = await tokenCollection.doc(normalizedPhone).get();
    if (tokenDoc.exists) {
      await tokenCollection.doc(normalizedPhone).delete();
    }
    res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    logger.error({ err: error }, 'Logout failure');
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
