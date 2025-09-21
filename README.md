# Truetag OTP Auth Backend

Secure OTP-based authentication service built with **Node.js (Express)**, **Firebase Admin (Firestore)**, and **hashed JWT + refresh tokens**. Includes endpoints to send OTP, verify/login, refresh JWT, logout, a protected profile endpoint, and a health check. Enhanced with rate limiting, brute-force protection, and security headers.

## Features
- Send one-time password (OTP) via MiMSMS
- Verify OTP and issue JWT + refresh token (both hashed before storage)
- Refresh access token with hashed refresh token validation
- Logout (revokes stored hashes)
- Protected profile endpoint (`/api/truetag/profile`) with hashed JWT verification
- Firestore persistence (separate collections for OTPs, tokens, and users)
- Rate limiting (global + per-phone OTP request limiting)
- Brute-force OTP attempt tracking & locking
- Opportunistic cleanup of expired OTP docs
- Security headers via Helmet
- Structured logging via Pino
- CORS enabled (adjust origin for production)
- Production friendly: `Procfile`, `package.json`, `.env.example`

## Tech Stack
- Node.js / Express
- Firebase Admin SDK (Firestore)
- MiMSMS SMS API
- JSON Web Tokens (JWT)
- bcrypt (hashing stored tokens)

## Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/truetag/send-otp` | Request an OTP (returns `sessionId`) |
| POST | `/api/truetag/verify-otp` | Verify OTP and receive `jwt`, `refreshToken`, `profile` |
| POST | `/api/truetag/refresh-token` | Exchange valid refresh token for new JWT |
| POST | `/api/truetag/logout` | Revoke tokens for a phone number |
| GET  | `/api/truetag/profile` | Fetch authenticated user profile |
| GET  | `/truetag/health` | Health check |

## Data Collections (Firestore)
| Collection | Purpose |
|------------|---------|
| `truetag_otps` | Temporary OTP docs (session-scoped) |
| `truetag_tokens` | Stores hashed `tokenHash` & `refreshTokenHash` per phone number |
| `truetag_users` | Basic user profile scaffold |

## Security Notes
- Raw JWT and refresh token are only sent once in response; only hashes are stored server-side (`bcrypt`).
- Refresh token is validated by signature first (JWT verify), then by bcrypt hash comparison.
- Access token also revalidated against stored hash (revocation support).
- OTPs expire (default 5 minutes) and are deleted after successful verification.
- OTP attempts tracked; session locks after configurable max attempts.
- Per-phone OTP request restriction plus global IP rate limit.
- Security headers with `helmet`; JSON body size limited to 10KB.
- Logging with `pino`; adjust verbosity via `LOG_LEVEL`.
- Use strong, secret values for `JWT_SECRET` and `REFRESH_TOKEN_SECRET` (32+ random bytes each).
- Consider deploying behind a WAF / API gateway for additional protection.

## Environment Variables
Copy `.env.example` to `.env` and replace placeholders.
```
# Choose one credential method:
FIREBASE_CREDENTIALS_FILE=./serviceAccount.json
# FIREBASE_CREDENTIALS_BASE64=ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIsIC4uLn0=
# FIREBASE_CREDENTIALS={"type":"service_account","project_id":"your-project-id",...}

SMS_USERNAME=...
SMS_API_KEY=...
SMS_SENDER_NAME=8809601003504
JWT_SECRET=your_strong_random_string
REFRESH_TOKEN_SECRET=your_other_strong_random_string
HASH_SALT_ROUNDS=12
OTP_TTL_MS=300000
OTP_MAX_ATTEMPTS=5
PHONE_OTP_WINDOW_MS=60000
PHONE_OTP_MAX_PER_WINDOW=3
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX=120
LOG_LEVEL=info
PORT=3001
```

Credential Methods (priority order):
1. File: place the downloaded service account JSON at `serviceAccount.json` and set `FIREBASE_CREDENTIALS_FILE`.
2. Base64: `base64 -w0 serviceAccount.json > creds.b64` then set `FIREBASE_CREDENTIALS_BASE64=$(cat creds.b64)`.
3. Field Variables (great for Render / dashboards): set all of
	- `FIREBASE_PROJECT_ID`
	- `FIREBASE_PRIVATE_KEY_ID`
	- `FIREBASE_PRIVATE_KEY` (replace real newlines with literal `\n` sequences)
	- `FIREBASE_CLIENT_EMAIL`
	- (optional) `FIREBASE_CLIENT_ID`
4. Raw JSON (least recommended): single-line minified JSON assigned to `FIREBASE_CREDENTIALS`.

Escape Private Key Example:
```
cat serviceAccount.json | jq -r .private_key | sed ':a;N;$!ba;s/\n/\\n/g'
```
Copy the output into the env var value for `FIREBASE_PRIVATE_KEY`.

If a key was ever committed publicly: revoke & reissue the service account key in Google Cloud Console immediately.

## Installation
```bash
git clone <repo-url>
cd truetp
npm install
```

## Run (Development)
```bash
cp .env.example .env   # then edit .env
npm run dev
```
Server starts on `http://localhost:3001` (override with `PORT`).

## Run (Production)
```bash
npm start
```

## Example cURL Usage
Request OTP:
```bash
curl -X POST http://localhost:3001/api/truetag/send-otp \
	-H 'Content-Type: application/json' \
	-d '{"phoneNumber":"+8801XXXXXXXXX"}'
```
Verify OTP:
```bash
curl -X POST http://localhost:3001/api/truetag/verify-otp \
	-H 'Content-Type: application/json' \
	-d '{"phoneNumber":"+8801XXXXXXXXX","otp":"123456","sessionId":"<sessionIdReturned>"}'
```
Refresh token:
```bash
curl -X POST http://localhost:3001/api/truetag/refresh-token \
	-H 'Content-Type: application/json' \
	-d '{"phoneNumber":"+8801XXXXXXXXX","refreshToken":"<refreshToken>"}'
```
Get profile (authenticated):
```bash
curl -X GET http://localhost:3001/api/truetag/profile \
  -H 'Authorization: Bearer <jwt>'
```
Logout:
```bash
curl -X POST http://localhost:3001/api/truetag/logout \
	-H 'Content-Type: application/json' \
	-d '{"phoneNumber":"+8801XXXXXXXXX"}'
```

## Deployment
### Render
1. Create a new Web Service -> Select this repo.
2. Build Command: `npm install`
3. Start Command: `npm start`
4. Set Environment Variables (recommended field-based method):
	- `FIREBASE_PROJECT_ID`
	- `FIREBASE_PRIVATE_KEY_ID`
	- `FIREBASE_PRIVATE_KEY` (paste with `\n` escapes)
	- `FIREBASE_CLIENT_EMAIL`
	- `FIREBASE_CLIENT_ID` (optional)
	- `JWT_SECRET`, `REFRESH_TOKEN_SECRET`
	- SMS variables, rate limit variables as needed.

If using Base64 method instead:
```
base64 -w0 serviceAccount.json > creds.b64
# copy the single line into FIREBASE_CREDENTIALS_BASE64
```

### Procfile-based Platforms (Heroku, Railway, etc.)
`Procfile` already present:
```
web: node server.js
```
Set env vars via the platform dashboard / CLI.

## Hardening Recommendations (Next Steps)
- Persist per-phone rate limiting counters in Firestore/Redis for multi-instance scaling.
- Add audit logging (e.g., to separate collection or external log system).
- Add monitoring/metrics (Prometheus exporter, OpenTelemetry traces).
- Implement secret rotation (JWT/refresh) & key versioning.
- Add CAPTCHA or silent device checks for high-risk scenarios.
- Implement background Cloud Function / cron to purge stale token docs.

## License
Proprietary / Internal (adjust as needed).

---
Generated scaffold for Truetag OTP auth backend. SMS format: "welcome to RR Kabel. your otp is XXXXXX".