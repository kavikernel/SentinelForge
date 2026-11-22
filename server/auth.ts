import crypto from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import type { PublicUser, UserRole } from '../src/shared/types.ts';

export interface StoredDemoUser {
  id: string;
  username: string;
  displayName: string;
  role: UserRole;
  salt: string;
  passwordHash: string;
  isDemoAccount: boolean;
}

export interface AuthenticatedRequest extends Request {
  authUser?: PublicUser;
}

const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

export function hashPassword(password: string, salt?: string): { salt: string; hash: string } {
  const actualSalt = salt ?? crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, actualSalt, 32).toString('hex');
  return { salt: actualSalt, hash };
}

export function verifyPassword(password: string, salt: string, expectedHash: string): boolean {
  const { hash } = hashPassword(password, salt);
  const bufA = Buffer.from(hash, 'hex');
  const bufB = Buffer.from(expectedHash, 'hex');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

export function createDefaultDemoUsers(): StoredDemoUser[] {
  const analystCreds = hashPassword('analyst-demo-2026', 'sf_analyst_salt_v1');
  const adminCreds = hashPassword('admin-demo-2026', 'sf_admin_salt_v1');
  return [
    {
      id: 'usr-analyst-demo',
      username: 'analyst',
      displayName: 'Maya Lin (Demo SOC Analyst)',
      role: 'analyst',
      salt: analystCreds.salt,
      passwordHash: analystCreds.hash,
      isDemoAccount: true,
    },
    {
      id: 'usr-admin-demo',
      username: 'admin',
      displayName: 'Dr. Aris Vance (Demo Administrator)',
      role: 'administrator',
      salt: adminCreds.salt,
      passwordHash: adminCreds.hash,
      isDemoAccount: true,
    },
  ];
}

export function toPublicUser(user: StoredDemoUser): PublicUser {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    role: user.role,
    isDemoAccount: user.isDemoAccount,
  };
}

export function signSessionToken(user: PublicUser): string {
  const payload = Buffer.from(
    JSON.stringify({
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      role: user.role,
      isDemoAccount: user.isDemoAccount,
      exp: Date.now() + 24 * 60 * 60 * 1000,
    })
  ).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

export function verifySessionToken(token: string): PublicUser | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as PublicUser & { exp: number };
    if (!parsed.exp || Date.now() > parsed.exp) return null;
    if (parsed.role !== 'analyst' && parsed.role !== 'administrator') return null;
    return {
      id: parsed.id,
      username: parsed.username,
      displayName: parsed.displayName,
      role: parsed.role,
      isDemoAccount: Boolean(parsed.isDemoAccount),
    };
  } catch {
    return null;
  }
}

export function attachAuthContext(req: AuthenticatedRequest, _res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    const user = verifySessionToken(token);
    if (user) {
      req.authUser = user;
    }
  }
  next();
}

export function requireRole(allowedRoles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.authUser) {
      res.status(401).json({
        error: 'Authentication required for this action. Sign in via the Demo Auth modal.',
        requiredRoles: allowedRoles,
      });
      return;
    }
    if (!allowedRoles.includes(req.authUser.role)) {
      res.status(403).json({
        error: `Permission denied: "${req.authUser.role}" role cannot perform this action. Requires: ${allowedRoles.join(' or ')}.`,
        requiredRoles: allowedRoles,
      });
      return;
    }
    next();
  };
}
