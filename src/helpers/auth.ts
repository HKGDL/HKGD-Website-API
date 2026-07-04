import { SignJWT, jwtVerify } from 'jose';
import { Bindings } from '../types';

const USER_JWT_EXPIRY = '7d';
const USER_JWT_EXPIRY_REMEMBER = '365d';

export async function createUserJwt(user: any, jwtSecret: string, rememberMe?: boolean): Promise<string> {
  return await new SignJWT({ userId: user.id, username: user.username, isAdmin: !!user.is_admin, timestamp: Date.now() })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime(rememberMe ? USER_JWT_EXPIRY_REMEMBER : USER_JWT_EXPIRY)
    .sign(new TextEncoder().encode(jwtSecret));
}

export async function authenticateToken(c: any, next: any) {
  const token = c.req.header('Authorization')?.replace('Bearer ', '') ||
                c.req.header('Cookie')?.match(/hkgd_admin_token=([^;]+)/)?.[1];
  if (!token) return c.json({ error: 'Access token required' }, 401);
  try {
    const secret = c.env.JWT_SECRET;
    if (!secret) return c.json({ error: 'Server configuration error' }, 500);
    const { payload } = await jwtVerify(token, new TextEncoder().encode(secret));
    if (!payload.isAdmin) return c.json({ error: 'Not authorized' }, 403);
    c.set('user', payload);
    await next();
  } catch {
    return c.json({ error: 'Invalid or expired token' }, 403);
  }
}

export async function authenticateUser(c: any, next: any) {
  const auth = c.req.header('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return c.json({ error: 'Access token required' }, 401);
  try {
    const secret = c.env.JWT_SECRET;
    if (!secret) return c.json({ error: 'Server configuration error' }, 500);
    const { payload } = await jwtVerify(auth.slice(7), new TextEncoder().encode(secret));
    c.set('user', payload);
    await next();
  } catch {
    return c.json({ error: 'Invalid or expired token' }, 403);
  }
}
