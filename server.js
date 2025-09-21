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
  const { FIREBASE_CREDENTIALS, FIREBASE_CREDENTIALS_BASE64, FIREBASE_CREDENTIALS_FILE } = process.env;
  let raw = FIREBASE_CREDENTIALS;
  if (!raw && FIREBASE_CREDENTIALS_BASE64) {
    try { raw = Buffer.from(FIREBASE_CREDENTIALS_BASE64, 'base64').toString('utf-8'); logger.info('Loaded Firebase credentials from BASE64 env'); } catch (e) { logger.warn('Failed to decode FIREBASE_CREDENTIALS_BASE64'); }
  }
  if (!raw && FIREBASE_CREDENTIALS_FILE) {
    try { raw = require('fs').readFileSync(FIREBASE_CREDENTIALS_FILE, 'utf-8'); logger.info({ file: FIREBASE_CREDENTIALS_FILE }, 'Loaded Firebase credentials from file'); } catch (e) { logger.warn({ file: FIREBASE_CREDENTIALS_FILE }, 'Failed to read FIREBASE_CREDENTIALS_FILE'); }
  }
  // Fallback: individual field env vars (better for platforms like Render)
  if (!raw) {
    const projectId = process.env.FIREBASE_PROJECT_ID;
    const privateKeyId = process.env.FIREBASE_PRIVATE_KEY_ID;
    let privateKey = process.env.FIREBASE_PRIVATE_KEY;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    const clientId = process.env.FIREBASE_CLIENT_ID;
    if (projectId && privateKeyId && privateKey && clientEmail) {
      // Support escaped \n in env var
      privateKey = privateKey.replace(/\\n/g, '\n');
      const credentialObj = {
        type: 'service_account',
        project_id: projectId,
        private_key_id: privateKeyId,
        private_key: privateKey,
        client_email: clientEmail,
        client_id: clientId || undefined,
        auth_uri: 'https://accounts.google.com/o/oauth2/auth',
        token_uri: 'https://oauth2.googleapis.com/token',
        auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
        client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(clientEmail)}`,
        universe_domain: 'googleapis.com'
      };
      return credentialObj;
    }
  }
  if (!raw) {
    throw new Error('No Firebase credentials found. Set one of FIREBASE_CREDENTIALS, FIREBASE_CREDENTIALS_BASE64, FIREBASE_CREDENTIALS_FILE');
  }
  if (raw.trim() === '{') {
    throw new Error('FIREBASE_CREDENTIALS appears to contain only an opening brace. If you tried to paste multi-line JSON directly into .env it will break. Use FIREBASE_CREDENTIALS_BASE64 or FIREBASE_CREDENTIALS_FILE instead.');
  }
  try {
    return JSON.parse(raw);
  } catch (e) {
    throw new Error(`Failed to parse Firebase credentials JSON: ${e.message}`);
  }
}

try {
  const credentials = loadFirebaseCredentials();
  admin.initializeApp({ credential: admin.credential.cert(credentials) });
} catch (error) {
  console.error('Error initializing Firebase:', error.message);
  process.exit(1);
}

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
const otpCollection = db.collection('jachai_otps');
const tokenCollection = db.collection('jachai_tokens');

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
app.post('/api/jachai/send-otp', async (req, res) => {
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
        Message: `Welcome to jachai. Your OTP is ${otp}`,
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
app.post('/api/jachai/verify-otp', async (req, res) => {
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

    // Check if user profile exists
    const userQuery = await db.collection('jachai_users')
      .where('phone_number', '==', phoneNumber)
      .limit(1)
      .get();

    let isProfileComplete = false;
    if (userQuery.empty) {
      await db.collection('jachai_users').add({
        phone_number: phoneNumber,
        name: '',
        image_url: '',
        editedby_user: false,
        created_at: Date.now(),
      });
    } else {
      const userData = userQuery.docs[0].data();
      isProfileComplete = userData.editedby_user === true;
    }

    logger.info({ phoneNumber }, 'OTP verified, tokens issued');
    res.status(200).json({ jwt: token, refreshToken, isProfileComplete });
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
app.get('/api/jachai/profile', authMiddleware, async (req, res) => {
  try {
    const phoneNumber = req.user.phoneNumber;
    const userSnap = await db.collection('jachai_users').where('phone_number', '==', phoneNumber).limit(1).get();
    if (userSnap.empty) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    const doc = userSnap.docs[0];
    const data = doc.data();
    res.status(200).json({ profile: { phone_number: data.phone_number, name: data.name, image_url: data.image_url, editedby_user: data.editedby_user } });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Refresh token endpoint
app.post('/api/jachai/refresh-token', async (req, res) => {
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

// Logout endpoint
app.post('/api/jachai/logout', async (req, res) => {
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
app.get('/jachai/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Jachai server running on port ${PORT}`);
});
