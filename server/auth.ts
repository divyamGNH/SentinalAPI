import { NextFunction, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt, { SignOptions } from 'jsonwebtoken';
import {
  createUser,
  findUserById,
  findUserByUsername,
  recordAuthEvent,
  updateUserPassword,
  type PublicUser,
} from './db';

declare global {
  namespace Express {
    interface Request {
      authUser?: PublicUser;
    }
  }
}

const jwtSecret = process.env.JWT_SECRET || 'sentinel-development-secret-change-me';
const expiresIn = (process.env.JWT_EXPIRES_IN || '8h') as SignOptions['expiresIn'];

if (!process.env.JWT_SECRET) {
  console.warn('JWT_SECRET is not set; using a development-only fallback secret.');
}

export async function ensureDefaultAdmin() {
  const username = (process.env.ADMIN_USERNAME || 'admin').trim().toLowerCase();
  const existing = await findUserByUsername(username);
  if (existing) return existing;

  const password = process.env.ADMIN_PASSWORD || 'sentinel123';
  const passwordHash = await bcrypt.hash(password, 12);
  return createUser({
    name: process.env.ADMIN_NAME || 'Security Admin',
    username,
    passwordHash,
    role: 'admin',
  });
}

export function issueToken(user: PublicUser) {
  return jwt.sign(
    { sub: String(user.id), username: user.username, role: user.role },
    jwtSecret,
    { expiresIn, issuer: 'sentinelapi', audience: 'sentinel-dashboard' }
  );
}

function readToken(req: Request) {
  const authorization = req.headers.authorization || '';
  if (authorization.startsWith('Bearer ')) return authorization.slice(7);
  const cookie = req.headers.cookie?.split(';').map(value => value.trim()).find(value => value.startsWith('sentinel_token='));
  return cookie ? decodeURIComponent(cookie.slice('sentinel_token='.length)) : '';
}

export async function optionalAuth(req: Request, _res: Response, next: NextFunction) {
  const token = readToken(req);
  if (!token) return next();

  try {
    const payload = jwt.verify(token, jwtSecret, {
      issuer: 'sentinelapi',
      audience: 'sentinel-dashboard',
    });
    if (typeof payload === 'string' || !payload.sub) return next();
    const user = await findUserById(Number(payload.sub));
    if (user?.active) req.authUser = user;
  } catch {
    // requireAuth returns the user-facing 401 response on protected routes.
  }
  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!req.authUser) return res.status(401).json({ error: 'Authentication required' });
  next();
}

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  if (req.authUser?.role !== 'admin') {
    return res.status(403).json({ error: 'Administrator access required' });
  }
  next();
}

export async function authenticate(usernameInput: string, password: string, req: Request) {
  const username = usernameInput.trim().toLowerCase();
  const userRecord = await findUserByUsername(username);
  const valid = Boolean(userRecord?.active && await bcrypt.compare(password, userRecord.password_hash));

  await recordAuthEvent({
    userId: userRecord?.id || null,
    username,
    eventType: valid ? 'login_success' : 'login_failure',
    sourceIp: req.ip || req.socket.remoteAddress || 'unknown',
    userAgent: req.headers['user-agent'] || '',
  });

  return valid && userRecord ? userRecord : null;
}

export async function hashPassword(password: string) {
  return bcrypt.hash(password, 12);
}

export function validatePassword(password: string) {
  return password.length >= 10 && /[A-Za-z]/.test(password) && /\d/.test(password);
}

export async function changePassword(userId: number, currentPassword: string, newPassword: string) {
  const user = await findUserById(userId, true);
  if (!user || !(await bcrypt.compare(currentPassword, user.password_hash))) return false;
  await updateUserPassword(userId, await hashPassword(newPassword));
  return true;
}
