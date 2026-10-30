const crypto = require('node:crypto');
const { promisify } = require('node:util');
const jwt = require('jsonwebtoken');

const scrypt = promisify(crypto.scrypt);
const ISSUER = 'spark-service';
const AUDIENCE = 'spark-portal';
const ACCESS_TOKEN_TTL_SECONDS = Number(process.env.JWT_ACCESS_TTL_SECONDS || 900);
const REFRESH_TOKEN_TTL_DAYS = Number(process.env.JWT_REFRESH_TTL_DAYS || 30);

function getJwtSecret() {
  return process.env.JWT_ACCESS_SECRET;
}

function assertAuthConfig() {
  const secret = getJwtSecret();
  if (!secret || Buffer.byteLength(secret) < 32) {
    throw new Error('Set JWT_ACCESS_SECRET to a random secret of at least 32 bytes.');
  }
  if (!Number.isInteger(ACCESS_TOKEN_TTL_SECONDS) || ACCESS_TOKEN_TTL_SECONDS < 60) {
    throw new Error('JWT_ACCESS_TTL_SECONDS must be an integer of at least 60.');
  }
  if (!Number.isInteger(REFRESH_TOKEN_TTL_DAYS) || REFRESH_TOKEN_TTL_DAYS < 1) {
    throw new Error('JWT_REFRESH_TTL_DAYS must be a positive integer.');
  }
}

function createAccessToken(user) {
  return jwt.sign(
    { role: user.role, emailKey: user.emailKey },
    getJwtSecret(),
    {
      algorithm: 'HS256',
      audience: AUDIENCE,
      expiresIn: ACCESS_TOKEN_TTL_SECONDS,
      issuer: ISSUER,
      subject: user.userId,
    },
  );
}

function authenticate(req, res, next) {
  const authorization = req.get('authorization') || '';
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return res.status(401).json({ error: 'A bearer access token is required.' });
  }

  try {
    const payload = jwt.verify(match[1], getJwtSecret(), {
      algorithms: ['HS256'],
      audience: AUDIENCE,
      issuer: ISSUER,
    });

    if (!payload.sub || !['applicant', 'manager', 'superAdmin'].includes(payload.role)) {
      return res.status(401).json({ error: 'Invalid access token.' });
    }

    req.auth = {
      userId: payload.sub,
      role: payload.role,
      emailKey: typeof payload.emailKey === 'string' ? payload.emailKey : undefined,
    };
    return next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired access token.' });
  }
}

function requireRoles(...roles) {
  return (req, res, next) => {
    if (!req.auth || !roles.includes(req.auth.role)) {
      return res.status(403).json({ error: 'You do not have permission to perform this action.' });
    }
    return next();
  };
}

function hashRefreshToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function safeHashEquals(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const leftBytes = Buffer.from(left, 'hex');
  const rightBytes = Buffer.from(right, 'hex');
  return leftBytes.length === rightBytes.length && crypto.timingSafeEqual(leftBytes, rightBytes);
}

function createRefreshToken(userId, sessionId) {
  return `${userId}.${sessionId}.${crypto.randomBytes(48).toString('base64url')}`;
}

function parseRefreshToken(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) return null;
  return { userId: parts[0], sessionId: parts[1] };
}

function refreshExpiry() {
  return new Date(Date.now() + REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();
}

async function verifyPassword(password, passwordHash) {
  if (typeof passwordHash !== 'string') return false;
  const [algorithm, salt, digest] = passwordHash.split('$');
  if (algorithm !== 'scrypt' || !salt || !digest || !/^[a-f0-9]+$/i.test(digest)) return false;

  const expected = Buffer.from(digest, 'hex');
  const actual = await scrypt(password, salt, expected.length);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function createAuthRouter(express, getContainers) {
  const router = express.Router();

  router.post('/login', async (req, res) => {
    const containers = getContainers();
    if (!containers) return res.status(503).json({ error: 'Cosmos DB is not configured.' });

    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = req.body?.password;
    if (!email || typeof password !== 'string') {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
      const { resource: user } = await containers.users.item('profile', email).read();
      if (!user || user.status !== 'active' || !(await verifyPassword(password, user.passwordHash))) {
        return res.status(401).json({ error: 'Invalid email or password.' });
      }

      const sessionId = crypto.randomUUID();
      const refreshToken = createRefreshToken(user.userId, sessionId);
      const now = new Date().toISOString();
      await containers.sessions.items.create({
        id: sessionId,
        userId: user.userId,
        emailKey: user.emailKey,
        refreshTokenHash: hashRefreshToken(refreshToken),
        createdAt: now,
        lastUsedAt: now,
        expiresAt: refreshExpiry(),
        revokedAt: null,
      });

      return res.json({
        tokenType: 'Bearer',
        accessToken: createAccessToken(user),
        expiresIn: ACCESS_TOKEN_TTL_SECONDS,
        refreshToken,
      });
    } catch (error) {
      if (error.code === 404 || error.statusCode === 404) {
        return res.status(401).json({ error: 'Invalid email or password.' });
      }
      console.error('Login failed:', error);
      return res.status(500).json({ error: 'Unable to log in.' });
    }
  });

  router.post('/refresh', async (req, res) => {
    const containers = getContainers();
    if (!containers) return res.status(503).json({ error: 'Cosmos DB is not configured.' });

    const refreshToken = req.body?.refreshToken;
    const tokenInfo = parseRefreshToken(refreshToken);
    if (!tokenInfo) return res.status(401).json({ error: 'Invalid refresh token.' });

    try {
      const { resource: session } = await containers.sessions
        .item(tokenInfo.sessionId, tokenInfo.userId)
        .read();
      if (!session || session.revokedAt || Date.parse(session.expiresAt) <= Date.now()) {
        return res.status(401).json({ error: 'Refresh token is expired or revoked.' });
      }
      if (!safeHashEquals(session.refreshTokenHash, hashRefreshToken(refreshToken))) {
        return res.status(401).json({ error: 'Invalid refresh token.' });
      }

      const { resource: user } = await containers.users.item('profile', session.emailKey).read();
      if (!user || user.status !== 'active' || user.userId !== tokenInfo.userId) {
        return res.status(401).json({ error: 'User is not active.' });
      }

      const nextRefreshToken = createRefreshToken(user.userId, session.id);
      const rotatedSession = {
        id: session.id,
        userId: session.userId,
        emailKey: session.emailKey,
        refreshTokenHash: hashRefreshToken(nextRefreshToken),
        createdAt: session.createdAt,
        lastUsedAt: new Date().toISOString(),
        expiresAt: refreshExpiry(),
        revokedAt: null,
      };
      await containers.sessions.item(session.id, session.userId).replace(rotatedSession, {
        accessCondition: { type: 'IfMatch', condition: session._etag },
      });

      return res.json({
        tokenType: 'Bearer',
        accessToken: createAccessToken(user),
        expiresIn: ACCESS_TOKEN_TTL_SECONDS,
        refreshToken: nextRefreshToken,
      });
    } catch (error) {
      if (error.code === 404 || error.statusCode === 404) {
        return res.status(401).json({ error: 'Invalid refresh token.' });
      }
      if (error.code === 412 || error.statusCode === 412) {
        return res.status(401).json({ error: 'Refresh token was already used.' });
      }
      console.error('Token refresh failed:', error.message);
      return res.status(500).json({ error: 'Unable to refresh token.' });
    }
  });

  router.post('/logout', async (req, res) => {
    const containers = getContainers();
    if (!containers) return res.status(503).json({ error: 'Cosmos DB is not configured.' });

    const refreshToken = req.body?.refreshToken;
    const tokenInfo = parseRefreshToken(refreshToken);
    if (!tokenInfo) return res.status(204).end();

    try {
      const { resource: session } = await containers.sessions
        .item(tokenInfo.sessionId, tokenInfo.userId)
        .read();
      if (session && !session.revokedAt && safeHashEquals(session.refreshTokenHash, hashRefreshToken(refreshToken))) {
        await containers.sessions.item(session.id, session.userId).replace({
          id: session.id,
          userId: session.userId,
          emailKey: session.emailKey,
          refreshTokenHash: null,
          createdAt: session.createdAt,
          lastUsedAt: session.lastUsedAt,
          expiresAt: session.expiresAt,
          revokedAt: new Date().toISOString(),
        }, {
          accessCondition: { type: 'IfMatch', condition: session._etag },
        });
      }
      return res.status(204).end();
    } catch (error) {
      if (error.code === 404 || error.statusCode === 404 || error.code === 412 || error.statusCode === 412) {
        return res.status(204).end();
      }
      console.error('Logout failed:', error.message);
      return res.status(500).json({ error: 'Unable to log out.' });
    }
  });

  return router;
}

module.exports = { assertAuthConfig, authenticate, createAuthRouter, requireRoles };
