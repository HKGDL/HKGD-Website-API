import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { secureHeaders } from 'hono/secure-headers';
import { SignJWT, jwtVerify } from 'jose';

type Bindings = {
  DB: D1Database;
  ENVIRONMENT: string;
  JWT_SECRET: string;
  ADMIN_PASSWORD: string;
  SUGGESTIONS_PASSWORD: string;
  MOTD_ADMIN_PASSWORD: string;
  INDEXNOW_KEY: string;
  SITE_HOSTNAME: string;
  GOOGLE_SHEETS_API_KEY?: string;
  GOOGLE_SHEET_ID?: string;
  GOOGLE_SHEET_RANGE?: string;
  DISCORD_BOT_TOKEN?: string;
  DISCORD_CHANNEL_ID?: string;
  RESEND_API_KEY?: string;
  SITE_URL?: string;
};

const app = new Hono<{ Bindings: Bindings }>();

app.use('*', logger());
app.use('*', secureHeaders());

app.use('*', cors({
  origin: (origin) => {
    const allowed = [
      'http://localhost:5173',
      'http://localhost:4173',
      'https://hkgdl.dpdns.org',
      'https://hkgd-website-frontend.hkgdl.workers.dev',
      'https://hkgdl-frontend-v2.pages.dev',
      'https://v2.hkgdl.dpdns.org',
      'https://hkgd-v2.hkgdl.workers.dev',
    ];
    if (!origin) return origin;
    if (allowed.some(a => origin === a || origin.startsWith(a))) return origin;
    if (origin.endsWith('.hkgdl.workers.dev')) return origin;
    if (origin.endsWith('.hkgdl.dpdns.org')) return origin;
    if (origin.startsWith('geode://')) return origin;
    return null;
  },
  credentials: true,
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
}));

app.get('/api', (c) => {
  return c.json({
    name: 'HKGD API',
    version: '1.0.0',
    endpoints: {
      levels: '/api/levels',
      platformer: '/api/platformer-levels',
      auth: '/api/auth/login',
      pending: '/api/pending',
      changelog: '/api/changelog',
    }
  });
});

// ── Helpers ──────────────────────────────────────────

function getClientIP(c: any): string {
  let ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ||
           c.req.header('x-real-ip')?.trim() ||
           '127.0.0.1';
  if (ip === '::1' || ip === '::ffff:127.0.0.1') ip = '127.0.0.1';
  if (ip.startsWith('::ffff:')) ip = ip.substring(7);
  return ip || '127.0.0.1';
}

const safe = (v: any) => (v === undefined ? null : v);

// ── IP Ban ───────────────────────────────────────────

const MAX_LOGIN_ATTEMPTS = 5;
const BAN_DURATION = 15 * 60 * 1000;

async function isIPBanned(db: D1Database, ip: string): Promise<{ banned: boolean; remainingTime?: number }> {
  const result = await db.prepare(
    'SELECT banned_until FROM ip_bans WHERE ip = ? AND banned_until > ?'
  ).bind(ip, Date.now()).first();
  if (result) {
    return { banned: true, remainingTime: Math.ceil((result.banned_until as number - Date.now()) / 1000) };
  }
  return { banned: false };
}

async function recordFailedLogin(db: D1Database, ip: string): Promise<number> {
  const existing = await db.prepare('SELECT attempts FROM ip_bans WHERE ip = ?').bind(ip).first();
  const attempts = (existing?.attempts as number || 0) + 1;
  const bannedUntil = attempts >= MAX_LOGIN_ATTEMPTS ? Date.now() + BAN_DURATION : 0;
  await db.prepare(`
    INSERT INTO ip_bans (ip, attempts, banned_until, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET
      attempts = excluded.attempts,
      banned_until = excluded.banned_until,
      updated_at = excluded.updated_at
  `).bind(ip, attempts, bannedUntil, Date.now()).run();
  return attempts;
}

async function resetFailedAttempts(db: D1Database, ip: string): Promise<void> {
  await db.prepare('DELETE FROM ip_bans WHERE ip = ?').bind(ip).run();
}

// ── IndexNow ─────────────────────────────────────────

const INDEXNOW_SEARCH_ENGINES = ['https://www.bing.com/indexnow'];

async function submitUrlToIndexNow(env: Bindings, url: string): Promise<void> {
  const key = env.INDEXNOW_KEY;
  if (!key) return;
  const hostname = env.SITE_HOSTNAME || 'hkgdl.dpdns.org';
  const siteUrl = url.startsWith('http') ? url : `https://${hostname}${url}`;
  for (const engine of INDEXNOW_SEARCH_ENGINES) {
    try {
      await fetch(`${engine}?url=${encodeURIComponent(siteUrl)}&key=${key}`, { method: 'GET' });
    } catch {}
  }
}

async function submitUrlsBatchToIndexNow(env: Bindings, urls: string[]): Promise<void> {
  const key = env.INDEXNOW_KEY;
  if (!key || urls.length === 0) return;
  const hostname = env.SITE_HOSTNAME || 'hkgdl.dpdns.org';
  const siteUrls = urls.map(u => u.startsWith('http') ? u : `https://${hostname}${u}`);
  const payload = { host: hostname, key, urlList: siteUrls };
  for (const engine of INDEXNOW_SEARCH_ENGINES) {
    try {
      await fetch(engine, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
        body: JSON.stringify(payload),
      });
    } catch {}
  }
}

function notifyContentChanged(env: Bindings, extraUrls?: string[]) {
  const urls: string[] = ['/'];
  if (extraUrls) urls.push(...extraUrls);
  submitUrlsBatchToIndexNow(env, urls).catch(() => {});
}

// ── Points ───────────────────────────────────────────

function computePoints(rank: number, totalLevels: number): number {
  if (!totalLevels || totalLevels <= 0) return 1;
  if (rank <= 0) rank = 1;
  if (rank > totalLevels) rank = totalLevels;
  return Math.max(1, Math.round(500 * (1 - Math.log10(rank) / Math.log10(totalLevels))));
}

// ── DB Init ──────────────────────────────────────────

async function initUserTables(db: D1Database): Promise<void> {
  try {
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        display_name TEXT,
        player_name TEXT,
        discord TEXT,
        email TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        read INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS claims (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        level_id TEXT NOT NULL,
        level_name TEXT NOT NULL,
        record_date TEXT,
        status TEXT DEFAULT 'pending',
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS reset_tokens (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at INTEGER NOT NULL,
        used INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);
    try { await db.exec("ALTER TABLE records ADD COLUMN points REAL"); } catch {}
    try { await db.exec("ALTER TABLE platformer_records ADD COLUMN points REAL"); } catch {}
  } catch (err) {
    console.error('Error initializing tables:', err);
  }
}

// ── Email (Resend) ───────────────────────────────────

async function sendEmail(apiKey: string, to: string, subject: string, html: string, text: string): Promise<boolean> {
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: 'HKGD Demon List <noreply@hkgdl.dpdns.org>', to: [to], subject, html, text }),
    });
    return res.ok;
  } catch { return false; }
}

async function sendPasswordResetEmail(apiKey: string, to: string, resetUrl: string): Promise<boolean> {
  const subject = 'Reset Your HKGD Account Password';
  const html = `<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto">
    <h2 style="color:#e74c3c">HKGD Demon List</h2>
    <p>You requested a password reset. Click the button below — this link expires in 5 minutes.</p>
    <a href="${resetUrl}" style="display:inline-block;padding:12px 24px;background:#e74c3c;color:#fff;text-decoration:none;border-radius:6px;margin:16px 0">Reset Password</a>
    <p style="color:#888;font-size:13px">If you didn't request this, ignore this email.</p></div>`;
  const text = `Reset your HKGD password: ${resetUrl}\n\nThis link expires in 5 minutes.`;
  return sendEmail(apiKey, to, subject, html, text);
}

// ── JWT Helpers ──────────────────────────────────────

const USER_JWT_EXPIRY = '7d';

async function createUserJwt(user: any, jwtSecret: string): Promise<string> {
  return await new SignJWT({ userId: user.id, username: user.username, isAdmin: false, timestamp: Date.now() })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime(USER_JWT_EXPIRY)
    .sign(new TextEncoder().encode(jwtSecret));
}

// Admin auth middleware
async function authenticateToken(c: any, next: any) {
  const token = c.req.header('Authorization')?.replace('Bearer ', '') ||
                c.req.header('Cookie')?.match(/hkgd_admin_token=([^;]+)/)?.[1];
  if (!token) return c.json({ error: 'Access token required' }, 401);
  try {
    const { payload } = await jwtVerify(token, new TextEncoder().encode(c.env.JWT_SECRET || 'hkgd-secret-key-2024'));
    c.set('user', payload);
    await next();
  } catch {
    return c.json({ error: 'Invalid or expired token' }, 403);
  }
}

// User auth middleware
async function authenticateUser(c: any, next: any) {
  const auth = c.req.header('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return c.json({ error: 'Access token required' }, 401);
  try {
    const { payload } = await jwtVerify(auth.slice(7), new TextEncoder().encode(c.env.JWT_SECRET || 'hkgd-secret-key-2024'));
    if (payload.isAdmin) return c.json({ error: 'Admin tokens not allowed on user endpoints' }, 403);
    c.set('user', payload);
    await next();
  } catch {
    return c.json({ error: 'Invalid or expired token' }, 403);
  }
}

// ── Admin Auth ───────────────────────────────────────

app.post('/api/auth/login', async (c) => {
  try {
    const { password } = await c.req.json();
    const ip = getClientIP(c);
    const adminPassword = c.env.ADMIN_PASSWORD;
    const suggestionsPassword = c.env.SUGGESTIONS_PASSWORD;
    const jwtSecret = c.env.JWT_SECRET;
    const motdPassword = c.env.MOTD_ADMIN_PASSWORD;

    if (!adminPassword || !suggestionsPassword || !jwtSecret) {
      return c.json({ error: 'Server configuration error' }, 500);
    }

    const { banned, remainingTime } = await isIPBanned(c.env.DB, ip);
    if (banned) {
      return c.json({ error: 'IP banned', message: `Too many failed login attempts. Try again in ${Math.floor(remainingTime! / 60)} minutes.`, remainingTime }, 403);
    }

    let role: any = null;
    if (password === adminPassword) role = true;
    else if (password === suggestionsPassword) role = 'suggestions';
    else if (motdPassword && password === motdPassword) role = 'motd';

    if (role !== null) {
      await resetFailedAttempts(c.env.DB, ip);
      const token = await new SignJWT({ isAdmin: role, timestamp: Date.now() })
        .setProtectedHeader({ alg: 'HS256' })
        .setExpirationTime('2h')
        .sign(new TextEncoder().encode(jwtSecret));
      return c.json({ success: true, user: { isAdmin: role }, token });
    }

    const attempts = await recordFailedLogin(c.env.DB, ip);
    return c.json({ success: false, error: 'Invalid password', attemptsRemaining: Math.max(0, MAX_LOGIN_ATTEMPTS - attempts), attempts }, 401);
  } catch (error) {
    console.error('Login error:', error);
    return c.json({ error: 'Login failed' }, 500);
  }
});

app.post('/api/auth/verify', authenticateToken, async (c: any) => {
  return c.json({ success: true, user: c.get('user') });
});

app.post('/api/auth/logout', async (c) => {
  return c.json({ success: true, message: 'Logged out successfully' });
});

// ── User Auth ────────────────────────────────────────

app.post('/api/user/register', async (c) => {
  try {
    const { username, password, email } = await c.req.json();
    if (!username || !password || !email) {
      return c.json({ error: 'Username, password, and email are required' }, 400);
    }
    if (username.length < 3 || username.length > 20) {
      return c.json({ error: 'Username must be 3-20 characters' }, 400);
    }
    if (password.length < 6) {
      return c.json({ error: 'Password must be at least 6 characters' }, 400);
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return c.json({ error: 'Invalid email format' }, 400);
    }

    const existing = await c.env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
    if (existing) return c.json({ error: 'Username already taken' }, 409);

    const emailExists = await c.env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (emailExists) return c.json({ error: 'Email already registered' }, 409);

    const id = `user-${crypto.randomUUID()}`;
    const now = new Date().toISOString();
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(password));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashedPassword = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    await c.env.DB.prepare(`
      INSERT INTO users (id, username, password, email, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(id, username, hashedPassword, email, now, now).run();

    const token = await createUserJwt({ id, username }, c.env.JWT_SECRET);
    return c.json({ success: true, token, user: { id, username, email } }, 201);
  } catch (error) {
    console.error('Register error:', error);
    return c.json({ error: 'Registration failed' }, 500);
  }
});

app.post('/api/user/login', async (c) => {
  try {
    const { username, password } = await c.req.json();
    if (!username || !password) return c.json({ error: 'Username and password required' }, 400);

    const ip = getClientIP(c);
    const { banned, remainingTime } = await isIPBanned(c.env.DB, ip);
    if (banned) {
      return c.json({ error: 'IP banned', message: `Too many failed login attempts. Try again in ${Math.floor(remainingTime! / 60)} minutes.` }, 403);
    }

    const user = await c.env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (!user) {
      await recordFailedLogin(c.env.DB, ip);
      return c.json({ error: 'Invalid username or password' }, 401);
    }

    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(password));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashedPassword = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    if (user.password !== hashedPassword) {
      await recordFailedLogin(c.env.DB, ip);
      return c.json({ error: 'Invalid username or password' }, 401);
    }

    await resetFailedAttempts(c.env.DB, ip);
    const token = await createUserJwt(user, c.env.JWT_SECRET);

    return c.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        displayName: user.display_name,
        playerName: user.player_name,
        discord: user.discord,
        email: user.email,
      }
    });
  } catch (error) {
    console.error('User login error:', error);
    return c.json({ error: 'Login failed' }, 500);
  }
});

app.get('/api/user/profile', authenticateUser, async (c: any) => {
  try {
    const { userId } = c.get('user');
    const user = await c.env.DB.prepare(
      'SELECT id, username, display_name, player_name, discord, email, created_at, updated_at FROM users WHERE id = ?'
    ).bind(userId).first();

    if (!user) return c.json({ error: 'User not found' }, 404);

    return c.json({
      id: user.id,
      username: user.username,
      displayName: user.display_name,
      playerName: user.player_name,
      discord: user.discord,
      email: user.email,
      createdAt: user.created_at,
      updatedAt: user.updated_at,
    });
  } catch (error) {
    console.error('Profile error:', error);
    return c.json({ error: 'Failed to fetch profile' }, 500);
  }
});

app.put('/api/user/profile', authenticateUser, async (c: any) => {
  try {
    const { userId } = c.get('user');
    const { displayName, playerName, discord, email } = await c.req.json();

    if (email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) return c.json({ error: 'Invalid email format' }, 400);
      const existing = await c.env.DB.prepare('SELECT id FROM users WHERE email = ? AND id != ?').bind(email, userId).first();
      if (existing) return c.json({ error: 'Email already in use' }, 409);
    }

    const now = new Date().toISOString();
    await c.env.DB.prepare(`
      UPDATE users SET display_name = ?, player_name = ?, discord = ?, email = ?, updated_at = ?
      WHERE id = ?
    `).bind(safe(displayName), safe(playerName), safe(discord), safe(email), now, userId).run();

    return c.json({ success: true, message: 'Profile updated' });
  } catch (error) {
    console.error('Profile update error:', error);
    return c.json({ error: 'Failed to update profile' }, 500);
  }
});

// ── Forgot / Reset Password ─────────────────────────

app.post('/api/user/forgot-password', async (c) => {
  try {
    const { email } = await c.req.json();
    if (!email) return c.json({ error: 'Email required' }, 400);

    const user = await c.env.DB.prepare('SELECT id, username FROM users WHERE email = ?').bind(email).first();
    if (!user) {
      return c.json({ success: true, message: 'If the email exists, a reset link has been sent.' });
    }

    const apiKey = c.env.RESEND_API_KEY;
    if (!apiKey) return c.json({ error: 'Email service not configured' }, 500);

    const token = crypto.randomUUID();
    const expiresAt = Date.now() + 5 * 60 * 1000;
    const now = new Date().toISOString();
    const tokenId = `rt-${crypto.randomUUID()}`;

    await c.env.DB.prepare(`
      INSERT INTO reset_tokens (id, user_id, token, expires_at, used, created_at)
      VALUES (?, ?, ?, ?, 0, ?)
    `).bind(tokenId, user.id, token, expiresAt, now).run();

    const siteUrl = c.env.SITE_URL || 'https://v2.hkgdl.dpdns.org';
    const resetUrl = `${siteUrl}/reset-password?token=${token}`;

    await sendPasswordResetEmail(apiKey, email, resetUrl);

    return c.json({ success: true, message: 'If the email exists, a reset link has been sent.' });
  } catch (error) {
    console.error('Forgot password error:', error);
    return c.json({ error: 'Failed to process request' }, 500);
  }
});

app.post('/api/user/reset-password', async (c) => {
  try {
    const { token, newPassword } = await c.req.json();
    if (!token || !newPassword) return c.json({ error: 'Token and new password required' }, 400);
    if (newPassword.length < 6) return c.json({ error: 'Password must be at least 6 characters' }, 400);

    const resetToken = await c.env.DB.prepare(
      'SELECT * FROM reset_tokens WHERE token = ? AND used = 0 AND expires_at > ?'
    ).bind(token, Date.now()).first();

    if (!resetToken) return c.json({ error: 'Invalid or expired token' }, 400);

    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(newPassword));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashedPassword = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    await c.env.DB.prepare('UPDATE users SET password = ? WHERE id = ?')
      .bind(hashedPassword, resetToken.user_id).run();

    await c.env.DB.prepare('UPDATE reset_tokens SET used = 1 WHERE id = ?')
      .bind(resetToken.id).run();

    return c.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    return c.json({ error: 'Failed to reset password' }, 500);
  }
});

// ── Notifications ────────────────────────────────────

app.get('/api/user/notifications', authenticateUser, async (c: any) => {
  try {
    const { userId } = c.get('user');
    const notifications = await c.env.DB.prepare(`
      SELECT id, type, title, message, read, created_at
      FROM notifications
      WHERE user_id = ?
      ORDER BY created_at DESC
    `).bind(userId).all();

    return c.json((notifications.results || []).map((n: any) => ({
      id: n.id,
      type: n.type,
      title: n.title,
      message: n.message,
      read: n.read === 1,
      createdAt: n.created_at,
    })));
  } catch (error) {
    console.error('Notifications error:', error);
    return c.json({ error: 'Failed to fetch notifications' }, 500);
  }
});

app.put('/api/user/notifications/:id/read', authenticateUser, async (c: any) => {
  try {
    const { userId } = c.get('user');
    await c.env.DB.prepare('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?')
      .bind(c.req.param('id'), userId).run();
    return c.json({ success: true });
  } catch (error) {
    console.error('Mark read error:', error);
    return c.json({ error: 'Failed to mark notification as read' }, 500);
  }
});

app.post('/api/user/notifications/read-all', authenticateUser, async (c: any) => {
  try {
    const { userId } = c.get('user');
    await c.env.DB.prepare('UPDATE notifications SET read = 1 WHERE user_id = ?')
      .bind(userId).run();
    return c.json({ success: true });
  } catch (error) {
    console.error('Read all error:', error);
    return c.json({ error: 'Failed to mark all as read' }, 500);
  }
});

async function createNotification(db: D1Database, userId: string, type: string, title: string, message: string): Promise<void> {
  const id = `notif-${crypto.randomUUID()}`;
  const now = new Date().toISOString();
  await db.prepare(`
    INSERT INTO notifications (id, user_id, type, title, message, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(id, userId, type, title, message, now).run();
}

// ── Claims ───────────────────────────────────────────

app.get('/api/user/claims', authenticateUser, async (c: any) => {
  try {
    const { userId } = c.get('user');
    const claims = await c.env.DB.prepare(`
      SELECT id, level_id, level_name, record_date, status, created_at
      FROM claims
      WHERE user_id = ?
      ORDER BY created_at DESC
    `).bind(userId).all();

    return c.json((claims.results || []).map((cl: any) => ({
      id: cl.id,
      levelId: cl.level_id,
      levelName: cl.level_name,
      recordDate: cl.record_date,
      status: cl.status,
      createdAt: cl.created_at,
    })));
  } catch (error) {
    console.error('Claims error:', error);
    return c.json({ error: 'Failed to fetch claims' }, 500);
  }
});

app.post('/api/user/claims', authenticateUser, async (c: any) => {
  try {
    const { userId, username } = c.get('user');
    const { levelId, levelName, recordDate } = await c.req.json();
    if (!levelId || !levelName) return c.json({ error: 'levelId and levelName required' }, 400);

    const id = `claim-${crypto.randomUUID()}`;
    const now = new Date().toISOString();

    await c.env.DB.prepare(`
      INSERT INTO claims (id, user_id, level_id, level_name, record_date, status, created_at)
      VALUES (?, ?, ?, ?, ?, 'pending', ?)
    `).bind(id, userId, levelId, levelName, safe(recordDate), now).run();

    const admins = await c.env.DB.prepare("SELECT id FROM users WHERE username LIKE 'HKGDAdmin%'").all();
    for (const admin of (admins.results || [])) {
      await createNotification(c.env.DB, (admin as any).id, 'claim',
        `New claim from ${username}`,
        `${username} claimed record on ${levelName}`
      );
    }

    return c.json({ success: true, id, message: 'Claim submitted' }, 201);
  } catch (error) {
    console.error('Create claim error:', error);
    return c.json({ error: 'Failed to submit claim' }, 500);
  }
});

// ── Admin: Claims ────────────────────────────────────

app.get('/api/admin/claims', authenticateToken, async (c: any) => {
  try {
    const { status } = c.req.query();
    let query = `
      SELECT c.id, c.level_id, c.level_name, c.record_date, c.status, c.created_at,
             u.id as userId, u.username, u.display_name as displayName
      FROM claims c
      JOIN users u ON c.user_id = u.id
    `;
    const params: any[] = [];
    if (status && ['pending', 'approved', 'rejected'].includes(status)) {
      query += ' WHERE c.status = ?';
      params.push(status);
    }
    query += ' ORDER BY c.created_at DESC';

    const claims = await c.env.DB.prepare(query).bind(...params).all();
    return c.json((claims.results || []).map((cl: any) => ({
      id: cl.id,
      levelId: cl.level_id,
      levelName: cl.level_name,
      recordDate: cl.record_date,
      status: cl.status,
      createdAt: cl.created_at,
      user: { id: cl.userId, username: cl.username, displayName: cl.displayName },
    })));
  } catch (error) {
    console.error('Admin claims error:', error);
    return c.json({ error: 'Failed to fetch claims' }, 500);
  }
});

app.put('/api/admin/claims/:id', authenticateToken, async (c: any) => {
  try {
    const { status } = await c.req.json();
    if (!['approved', 'rejected'].includes(status)) {
      return c.json({ error: 'Status must be approved or rejected' }, 400);
    }

    const claim = await c.env.DB.prepare('SELECT * FROM claims WHERE id = ?').bind(c.req.param('id')).first();
    if (!claim) return c.json({ error: 'Claim not found' }, 404);

    await c.env.DB.prepare('UPDATE claims SET status = ? WHERE id = ?').bind(status, claim.id).run();

    await createNotification(c.env.DB, (claim as any).user_id, 'claim_status',
      `Claim ${status}`,
      `Your claim on ${(claim as any).level_name} has been ${status}.`
    );

    return c.json({ success: true, message: `Claim ${status}` });
  } catch (error) {
    console.error('Update claim error:', error);
    return c.json({ error: 'Failed to update claim' }, 500);
  }
});

// ── Admin: Users ─────────────────────────────────────

app.get('/api/admin/users', authenticateToken, async (c: any) => {
  try {
    const { search } = c.req.query();
    let query = 'SELECT id, username, display_name, player_name, discord, email, created_at FROM users';
    const params: any[] = [];
    if (search) {
      query += ' WHERE username LIKE ? OR display_name LIKE ? OR player_name LIKE ? OR email LIKE ?';
      const s = `%${search}%`;
      params.push(s, s, s, s);
    }
    query += ' ORDER BY created_at DESC';

    const users = await c.env.DB.prepare(query).bind(...params).all();
    return c.json((users.results || []).map((u: any) => ({
      id: u.id,
      username: u.username,
      displayName: u.display_name,
      playerName: u.player_name,
      discord: u.discord,
      email: u.email,
      createdAt: u.created_at,
    })));
  } catch (error) {
    console.error('Admin users error:', error);
    return c.json({ error: 'Failed to fetch users' }, 500);
  }
});

app.delete('/api/admin/users/:id', authenticateToken, async (c: any) => {
  try {
    const userId = c.req.param('id');
    const user = await c.env.DB.prepare('SELECT id, username FROM users WHERE id = ?').bind(userId).first();
    if (!user) return c.json({ error: 'User not found' }, 404);

    await c.env.DB.prepare('DELETE FROM notifications WHERE user_id = ?').bind(userId).run();
    await c.env.DB.prepare('DELETE FROM claims WHERE user_id = ?').bind(userId).run();
    await c.env.DB.prepare('DELETE FROM reset_tokens WHERE user_id = ?').bind(userId).run();
    await c.env.DB.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();

    return c.json({ success: true, message: `User ${(user as any).username} deleted` });
  } catch (error) {
    console.error('Delete user error:', error);
    return c.json({ error: 'Failed to delete user' }, 500);
  }
});

// ── Levels ───────────────────────────────────────────

app.get('/api/levels', async (c) => {
  try {
    const levels = await c.env.DB.prepare(`
      SELECT
        id, hkgd_rank as hkgdRank, aredl_rank as aredlRank, pemonlist_rank as pemonlistRank,
        name, creator, verifier, level_id as levelId, description, thumbnail,
        song_id as songId, song_name as songName, tags, date_added as dateAdded,
        pack, gddl_tier as gddlTier, nlw_tier as nlwTier, edel_enjoyment as edelEnjoyment
      FROM levels
      ORDER BY hkgd_rank ASC
    `).all();

    const allRecords = await c.env.DB.prepare(`
      SELECT id, level_id, player, date, video_url as videoUrl, fps, cbf, attempts, points
      FROM records
      ORDER BY date DESC
    `).all();

    const recordsByLevel: Record<string, any[]> = {};
    for (const r of (allRecords.results || [])) {
      if (!recordsByLevel[r.level_id as string]) {
        recordsByLevel[r.level_id as string] = [];
      }
      recordsByLevel[r.level_id as string].push({ ...r, cbf: r.cbf === 1 });
    }

    const levelsWithRecords = (levels.results || []).map((level: any) => ({
      ...level,
      songName: level.songName && level.songName !== 'undefined by undefined' ? level.songName : null,
      tags: level.tags ? JSON.parse(level.tags) : [],
      records: recordsByLevel[level.id] || [],
    }));

    return c.json(levelsWithRecords);
  } catch (error) {
    console.error('Error fetching levels:', error);
    return c.json({ error: 'Failed to fetch levels' }, 500);
  }
});

app.get('/api/levels/:id', async (c) => {
  try {
    const level = await c.env.DB.prepare(`
      SELECT
        id, hkgd_rank as hkgdRank, aredl_rank as aredlRank, pemonlist_rank as pemonlistRank,
        name, creator, verifier, level_id as levelId, description, thumbnail,
        song_id as songId, song_name as songName, tags, date_added as dateAdded,
        pack, gddl_tier as gddlTier, nlw_tier as nlwTier, edel_enjoyment as edelEnjoyment
      FROM levels
      WHERE id = ?
    `).bind(c.req.param('id')).first();

    if (!level) return c.json({ error: 'Level not found' }, 404);

    const records = await c.env.DB.prepare(`
      SELECT id, player, date, video_url as videoUrl, fps, cbf, attempts, points
      FROM records
      WHERE level_id = ?
      ORDER BY date DESC
    `).bind(c.req.param('id')).all();

    return c.json({
      ...level,
      tags: (level.tags as string) ? JSON.parse(level.tags as string) : [],
      records: (records.results || []).map((r: any) => ({ ...r, cbf: r.cbf === 1 })),
    });
  } catch (error) {
    console.error('Error fetching level:', error);
    return c.json({ error: 'Failed to fetch level' }, 500);
  }
});

app.post('/api/levels', authenticateToken, async (c) => {
  try {
    const data = await c.req.json();
    const { id, hkgdRank, aredlRank, pemonlistRank, name, creator, verifier, levelId,
            description, thumbnail, songId, songName, tags, dateAdded, pack, gddlTier, nlwTier, edelEnjoyment } = data;

    await c.env.DB.prepare(`
      INSERT INTO levels (id, hkgd_rank, aredl_rank, pemonlist_rank, name, creator, verifier, level_id,
        description, thumbnail, song_id, song_name, tags, date_added, pack, gddl_tier, nlw_tier, edel_enjoyment)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      safe(id), safe(hkgdRank), safe(aredlRank), safe(pemonlistRank),
      safe(name), safe(creator), safe(verifier), safe(levelId),
      safe(description), safe(thumbnail), safe(songId), safe(songName),
      JSON.stringify(tags || []), safe(dateAdded), safe(pack), safe(gddlTier), safe(nlwTier), safe(edelEnjoyment)
    ).run();

    notifyContentChanged(c.env);
    return c.json({ id, message: 'Level created successfully' }, 201);
  } catch (error) {
    console.error('Error creating level:', error);
    return c.json({ error: 'Failed to create level', details: error instanceof Error ? error.message : 'Unknown error' }, 500);
  }
});

app.put('/api/levels/:id', authenticateToken, async (c) => {
  try {
    const data = await c.req.json();
    const { hkgdRank, aredlRank, pemonlistRank, name, creator, verifier, levelId,
            description, thumbnail, songId, songName, tags, dateAdded, pack, gddlTier, nlwTier } = data;

    await c.env.DB.prepare(`
      UPDATE levels SET
        hkgd_rank = ?, aredl_rank = ?, pemonlist_rank = ?, name = ?, creator = ?, verifier = ?,
        level_id = ?, description = ?, thumbnail = ?, song_id = ?, song_name = ?,
        tags = ?, date_added = ?, pack = ?, gddl_tier = ?, nlw_tier = ?
      WHERE id = ?
    `).bind(
      safe(hkgdRank), safe(aredlRank), safe(pemonlistRank),
      safe(name), safe(creator), safe(verifier), safe(levelId),
      safe(description), safe(thumbnail), safe(songId), safe(songName),
      JSON.stringify(tags || []), safe(dateAdded), safe(pack), safe(gddlTier), safe(nlwTier),
      c.req.param('id')
    ).run();

    notifyContentChanged(c.env);
    return c.json({ message: 'Level updated successfully' });
  } catch (error) {
    console.error('Error updating level:', error);
    return c.json({ error: 'Failed to update level' }, 500);
  }
});

app.delete('/api/levels/:id', authenticateToken, async (c) => {
  try {
    await c.env.DB.prepare('DELETE FROM levels WHERE id = ?').bind(c.req.param('id')).run();
    notifyContentChanged(c.env);
    return c.json({ message: 'Level deleted successfully' });
  } catch (error) {
    console.error('Error deleting level:', error);
    return c.json({ error: 'Failed to delete level' }, 500);
  }
});

// ── Records ──────────────────────────────────────────

app.post('/api/levels/:levelId/records', authenticateToken, async (c) => {
  try {
    const body = await c.req.json();
    const player = body.player;
    const date = body.date;
    const videoUrl = body.videoUrl || body.video_url;
    const fps = body.fps;
    const cbf = body.cbf;
    const attempts = body.attempts;

    let points: number | null = null;
    const level = await c.env.DB.prepare('SELECT id, hkgd_rank FROM levels WHERE id = ?').bind(c.req.param('levelId')).first();
    if (level && (level as any).hkgd_rank) {
      const totalLevelsResult = await c.env.DB.prepare('SELECT COUNT(*) as count FROM levels WHERE hkgd_rank IS NOT NULL').first();
      const totalLevels = (totalLevelsResult as any)?.count || 0;
      points = computePoints((level as any).hkgd_rank, totalLevels);
    }

    const result = await c.env.DB.prepare(`
      INSERT INTO records (level_id, player, date, video_url, fps, cbf, attempts, points)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      c.req.param('levelId'), safe(player), safe(date), safe(videoUrl),
      safe(fps), cbf ? 1 : 0, safe(attempts), safe(points)
    ).run();

    notifyContentChanged(c.env);
    return c.json({ message: 'Record added successfully', id: result.meta.last_row_id, points }, 201);
  } catch (error) {
    console.error('Error adding record:', error);
    return c.json({ error: 'Failed to add record' }, 500);
  }
});

app.put('/api/records/:recordId', authenticateToken, async (c) => {
  try {
    const data = await c.req.json();
    const recordId = c.req.param('recordId');
    const updates: string[] = [];
    const values: any[] = [];

    const fields = ['player', 'date', 'video_url', 'fps', 'cbf', 'attempts', 'points'];
    const dataMap: any = {
      player: data.player, date: data.date, video_url: data.videoUrl,
      fps: data.fps, cbf: data.cbf ? 1 : 0, attempts: data.attempts, points: data.points,
    };

    for (const field of fields) {
      if (dataMap[field] !== undefined) {
        updates.push(`${field} = ?`);
        values.push(dataMap[field]);
      }
    }

    if (updates.length === 0) return c.json({ error: 'No fields to update' }, 400);

    values.push(parseInt(recordId));
    const result = await c.env.DB.prepare(`UPDATE records SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();

    if (result.meta.changes === 0) return c.json({ error: 'Record not found' }, 404);
    return c.json({ message: 'Record updated successfully' });
  } catch (error) {
    console.error('Error updating record:', error);
    return c.json({ error: 'Failed to update record', details: error instanceof Error ? error.message : 'Unknown error' }, 500);
  }
});

app.delete('/api/records/:recordId', authenticateToken, async (c) => {
  try {
    const recordId = parseInt(c.req.param('recordId'));
    const result = await c.env.DB.prepare('DELETE FROM records WHERE id = ?').bind(recordId).run();
    if (result.meta.changes === 0) return c.json({ error: 'Record not found' }, 404);
    return c.json({ message: 'Record deleted successfully' });
  } catch (error) {
    console.error('Error deleting record:', error);
    return c.json({ error: 'Failed to delete record' }, 500);
  }
});

// ── Points Recalculation ─────────────────────────────

app.post('/api/admin/recalculate-points', authenticateToken, async (c: any) => {
  try {
    const totalLevelsResult = await c.env.DB.prepare('SELECT COUNT(*) as count FROM levels WHERE hkgd_rank IS NOT NULL').first();
    const totalLevels = (totalLevelsResult as any)?.count || 0;
    if (totalLevels === 0) return c.json({ error: 'No levels found' }, 400);

    const levels = await c.env.DB.prepare('SELECT id, hkgd_rank FROM levels WHERE hkgd_rank IS NOT NULL').all();
    let updated = 0;

    for (const level of (levels.results || [])) {
      const points = computePoints((level as any).hkgd_rank, totalLevels);
      await c.env.DB.prepare('UPDATE records SET points = ? WHERE level_id = ? AND (points IS NULL OR points != ?)')
        .bind(points, (level as any).id, points).run();
      updated++;
    }

    return c.json({ success: true, message: `Recalculated points for ${updated} levels` });
  } catch (error) {
    console.error('Recalculate points error:', error);
    return c.json({ error: 'Failed to recalculate points' }, 500);
  }
});

// ── Members ──────────────────────────────────────────

app.get('/api/members', async (c) => {
  try {
    const members = await c.env.DB.prepare(`
      SELECT id, name, country, levels_beaten as levelsBeaten, avatar
      FROM members
      ORDER BY levels_beaten DESC
    `).all();
    return c.json(members.results || []);
  } catch (error) {
    console.error('Error fetching members:', error);
    return c.json({ error: 'Failed to fetch members' }, 500);
  }
});

// ── Player Mapping ───────────────────────────────────

app.get('/api/player-mapping', async (c) => {
  try {
    const { gameName } = c.req.query();
    if (!gameName) return c.json({ error: 'gameName parameter required' }, 400);

    const mapping = await c.env.DB.prepare(
      'SELECT db_name, account_id FROM player_mappings WHERE LOWER(game_name) = LOWER(?)'
    ).bind(gameName.toString()).first();

    return c.json({
      dbName: mapping?.db_name || gameName,
      accountId: mapping?.account_id || null,
      isMapped: !!mapping,
    });
  } catch (error) {
    console.error('Error fetching player mapping:', error);
    return c.json({ error: 'Failed to fetch player mapping' }, 500);
  }
});

app.post('/api/player-mapping', authenticateToken, async (c) => {
  try {
    const { gameName, dbName, accountId } = await c.req.json();
    if (!gameName || !dbName) return c.json({ error: 'gameName and dbName are required' }, 400);

    await c.env.DB.prepare(`
      INSERT INTO player_mappings (game_name, db_name, account_id)
      VALUES (?, ?, ?)
      ON CONFLICT(game_name) DO UPDATE SET
        db_name = excluded.db_name,
        account_id = excluded.account_id
    `).bind(gameName, dbName, accountId || null).run();

    return c.json({ success: true, gameName, dbName });
  } catch (error) {
    console.error('Error creating player mapping:', error);
    return c.json({ error: 'Failed to create player mapping' }, 500);
  }
});

app.get('/api/player-mappings', authenticateToken, async (c) => {
  try {
    const result = await c.env.DB.prepare(`
      SELECT id, game_name as gameName, db_name as dbName, account_id as accountId, created_at as createdAt
      FROM player_mappings
      ORDER BY created_at DESC
    `).all();
    return c.json(result.results || []);
  } catch (error) {
    console.error('Error fetching player mappings:', error);
    return c.json({ error: 'Failed to fetch player mappings' }, 500);
  }
});

app.delete('/api/player-mapping/:id', authenticateToken, async (c) => {
  try {
    await c.env.DB.prepare('DELETE FROM player_mappings WHERE id = ?').bind(c.req.param('id')).run();
    return c.json({ success: true });
  } catch (error) {
    console.error('Error deleting player mapping:', error);
    return c.json({ error: 'Failed to delete player mapping' }, 500);
  }
});

// ── Changelog ────────────────────────────────────────

app.get('/api/changelog', async (c) => {
  try {
    const changelog = await c.env.DB.prepare(`
      SELECT id, date, level_name as levelName, level_id as levelId,
        change_type as change, old_rank as oldRank, new_rank as newRank,
        description, list_type as listType
      FROM changelog
      ORDER BY date DESC
    `).all();
    return c.json(changelog.results || []);
  } catch (error) {
    console.error('Error fetching changelog:', error);
    return c.json({ error: 'Failed to fetch changelog' }, 500);
  }
});

app.post('/api/changelog', authenticateToken, async (c) => {
  try {
    const { id, date, levelName, levelId, change, oldRank, newRank, description, listType } = await c.req.json();
    await c.env.DB.prepare(`
      INSERT INTO changelog (id, date, level_name, level_id, change_type, old_rank, new_rank, description, list_type)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(id, date, levelName, levelId, change, safe(oldRank), safe(newRank), description, listType || 'classic').run();
    return c.json({ id, message: 'Changelog entry created successfully' }, 201);
  } catch (error) {
    console.error('Error creating changelog entry:', error);
    return c.json({ error: 'Failed to create changelog entry' }, 500);
  }
});

app.delete('/api/changelog/:id', authenticateToken, async (c) => {
  try {
    await c.env.DB.prepare('DELETE FROM changelog WHERE id = ?').bind(c.req.param('id')).run();
    return c.json({ message: 'Changelog entry deleted successfully' });
  } catch (error) {
    console.error('Error deleting changelog entry:', error);
    return c.json({ error: 'Failed to delete changelog entry' }, 500);
  }
});

// ── Content ──────────────────────────────────────────

app.get('/api/content', async (c) => {
  try {
    const contentRow = await c.env.DB.prepare("SELECT content_json FROM website_content WHERE id = 'main'").first();
    if (contentRow) return c.json(JSON.parse(contentRow.content_json as string));

    return c.json({
      hero: { title: 'HKGD DEMON LIST', subtitle: 'Hong Kong Geometry Dash Community' },
      stats: { levelsLabel: 'Levels Listed', playersLabel: 'Players', hardestLabel: 'Hardest AREDL' },
      listPage: { title: 'Demon List', description: 'All Extreme Demon levels beaten by HKGD members.' },
      platformerPage: { title: 'Platformer Demon List' },
      submitPage: { title: 'Submit Record' },
      footer: { description: 'The official demon list for the Hong Kong Geometry Dash community.' },
    });
  } catch (error) {
    console.error('Error fetching content:', error);
    return c.json({ error: 'Failed to fetch content' }, 500);
  }
});

app.post('/api/content', authenticateToken, async (c) => {
  try {
    const content = await c.req.json();
    const updated_at = new Date().toISOString();
    await c.env.DB.prepare(`
      INSERT INTO website_content (id, content_json, updated_at)
      VALUES ('main', ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        content_json = excluded.content_json,
        updated_at = excluded.updated_at
    `).bind(JSON.stringify(content), updated_at).run();
    return c.json({ message: 'Content saved successfully' });
  } catch (error) {
    console.error('Error saving content:', error);
    return c.json({ error: 'Failed to save content' }, 500);
  }
});

// ── Pending Submissions ──────────────────────────────

app.get('/api/pending-submissions', async (c) => {
  try {
    const submissions = await c.env.DB.prepare(
      "SELECT * FROM pending_submissions WHERE status = 'pending' ORDER BY submitted_at DESC"
    ).all();

    return c.json((submissions.results || []).map((s: any) => ({
      id: s.id,
      levelId: s.level_id,
      levelName: s.level_name,
      isNewLevel: s.is_new_level === 1,
      record: JSON.parse(s.record_data),
      levelData: s.level_data ? JSON.parse(s.level_data) : null,
      submittedAt: s.submitted_at,
      submittedBy: s.submitted_by,
      status: s.status,
      isPlatformer: s.is_platformer === 1,
      adminDecidesDifficulty: s.admin_decides_difficulty === 1,
    })));
  } catch (error) {
    console.error('Error fetching submissions:', error);
    return c.json({ error: 'Failed to fetch submissions' }, 500);
  }
});

app.post('/api/pending-submissions', async (c) => {
  try {
    const data = await c.req.json();
    const { id, levelId, levelName, isNewLevel, record, record_data, level_data, submittedAt, submittedBy, status } = data;
    const actualRecordData = record_data || JSON.stringify(record);
    const actualLevelData = level_data ? JSON.stringify(level_data) : null;

    await c.env.DB.prepare(`
      INSERT INTO pending_submissions (id, level_id, level_name, is_new_level, record_data, level_data, submitted_at, submitted_by, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(id, levelId, levelName, isNewLevel ? 1 : 0, actualRecordData, actualLevelData, submittedAt, submittedBy, status || 'pending').run();

    return c.json({ success: true, id, message: 'Submission created successfully' }, 201);
  } catch (error) {
    console.error('Error creating submission:', error);
    return c.json({ error: 'Failed to create submission' }, 500);
  }
});

app.post('/api/platformer-submissions', async (c) => {
  try {
    const data = await c.req.json();
    const { id, levelId, levelName, isNewLevel, record_data, submittedAt, submittedBy, status, adminDecidesDifficulty } = data;

    await c.env.DB.prepare(`
      INSERT INTO pending_submissions (id, level_id, level_name, is_new_level, record_data, level_data, submitted_at, submitted_by, status, is_platformer, admin_decides_difficulty)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(id, levelId, levelName, isNewLevel ? 1 : 0, record_data, null, submittedAt, submittedBy, status || 'pending', 1, adminDecidesDifficulty ? 1 : 0).run();

    return c.json({
      success: true, id,
      message: 'Platformer submission created successfully. Admin will review and decide difficulty placement.',
      requiresAdminReview: true, adminDecidesDifficulty: true,
    }, 201);
  } catch (error) {
    console.error('Error creating platformer submission:', error);
    return c.json({ error: 'Failed to create platformer submission', details: error instanceof Error ? error.message : 'Unknown error' }, 500);
  }
});

app.put('/api/pending-submissions/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const { status } = await c.req.json();
    if (!['pending', 'approved', 'rejected'].includes(status)) return c.json({ error: 'Invalid status' }, 400);

    await c.env.DB.prepare('UPDATE pending_submissions SET status = ? WHERE id = ?').bind(status, id).run();
    return c.json({ success: true, message: 'Submission updated successfully' });
  } catch (error) {
    console.error('Error updating submission:', error);
    return c.json({ error: 'Failed to update submission' }, 500);
  }
});

// ── Platformer Levels ────────────────────────────────

app.get('/api/platformer-demons', async (c) => {
  try {
    const levels = await c.env.DB.prepare(`
      SELECT id, hkgd_rank as hkgdRank, name, creator, verifier, level_id as levelId, description, thumbnail,
        song_id as songId, song_name as songName, tags, date_added as dateAdded, pack, difficulty
      FROM platformer_levels
      ORDER BY hkgd_rank ASC
    `).all();
    return c.json({ demons: levels.results || [] });
  } catch (error) {
    console.error('Error fetching platformer demons:', error);
    return c.json({ error: 'Failed to fetch platformer demons' }, 500);
  }
});

// ── GDBrowser / History GD Proxy ─────────────────────

app.get('/api/gdbrowser/level/:levelId', async (c) => {
  try {
    const levelId = c.req.param('levelId');
    const response = await fetch(`https://history.geometrydash.eu/api/v1/search/level/advanced/?query=${levelId}&limit=1&filter=online_id%3D${levelId}`);
    if (response.ok) {
      const data = await response.json() as any;
      if (data.hits && data.hits.length > 0) return c.json(data.hits[0]);
      return c.json({ error: 'Level not found' }, 404);
    }
    const gdbResponse = await fetch(`https://www.gdbrowser.com/api/level/${levelId}?key=Wmfd2893gb7`, {
      headers: { 'User-Agent': '', 'Accept': 'application/json' },
    });
    const gdbData = await gdbResponse.text();
    if (gdbData.startsWith('<') || gdbData.startsWith('-1') || gdbData.startsWith('Not Found')) {
      return c.json({ error: 'Level not found' }, 404);
    }
    try { return c.json(JSON.parse(gdbData)); } catch { return c.json({ error: 'Invalid response' }, 500); }
  } catch (error) {
    console.error('Error fetching level:', error);
    return c.json({ error: 'Failed to fetch level' }, 500);
  }
});

app.get('/api/gdbrowser/search', async (c) => {
  try {
    const query = c.req.query('q');
    if (!query) return c.json({ error: 'Query required' }, 400);
    const filter = 'cache_length=5';
    const response = await fetch(`https://history.geometrydash.eu/api/v1/search/level/advanced/?query=${encodeURIComponent(query)}&limit=20&filter=${encodeURIComponent(filter)}`);
    if (response.ok) {
      const data = await response.json() as any;
      return c.json(data.hits || []);
    }
    return c.json({ error: 'Search failed' }, 500);
  } catch (error) {
    console.error('Error searching:', error);
    return c.json({ error: 'Failed to search' }, 500);
  }
});

// ── Settings ─────────────────────────────────────────

app.get('/api/settings', async (c) => {
  try {
    const settings = await c.env.DB.prepare('SELECT key, value FROM settings').all();
    const settingsMap: Record<string, boolean> = {};
    for (const s of (settings.results || [])) {
      settingsMap[s.key as string] = s.value === 'true';
    }
    return c.json(settingsMap);
  } catch (error) {
    console.error('Error fetching settings:', error);
    return c.json({ error: 'Failed to fetch settings' }, 500);
  }
});

app.put('/api/settings/:key', authenticateToken, async (c) => {
  try {
    const key = c.req.param('key');
    const { value } = await c.req.json();
    const updated_at = new Date().toISOString();
    await c.env.DB.prepare(`
      INSERT INTO settings (key, value, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        value = excluded.value,
        updated_at = excluded.updated_at
    `).bind(key, value ? 'true' : 'false', updated_at).run();
    return c.json({ message: 'Setting updated successfully', key, value });
  } catch (error) {
    console.error('Error updating setting:', error);
    return c.json({ error: 'Failed to update setting' }, 500);
  }
});

// ── IP Bans ──────────────────────────────────────────

app.get('/api/ip-bans', authenticateToken, async (c) => {
  try {
    const bans = await c.env.DB.prepare(`SELECT ip, attempts, banned_until, updated_at FROM ip_bans ORDER BY updated_at DESC`).all();
    const now = Date.now();
    return c.json((bans.results || []).map((ban: any) => ({
      ip: ban.ip,
      attempts: ban.attempts,
      bannedUntil: ban.banned_until,
      isCurrentlyBanned: ban.banned_until > now,
      remainingTime: ban.banned_until > now ? Math.ceil((ban.banned_until - now) / 1000) : 0,
      updatedAt: ban.updated_at,
    })));
  } catch (error) {
    console.error('Error fetching IP bans:', error);
    return c.json({ error: 'Failed to fetch IP bans' }, 500);
  }
});

app.delete('/api/ip-bans/:ip', authenticateToken, async (c) => {
  try {
    await c.env.DB.prepare('DELETE FROM ip_bans WHERE ip = ?').bind(c.req.param('ip')).run();
    return c.json({ message: 'IP unbanned successfully', ip: c.req.param('ip') });
  } catch (error) {
    console.error('Error unbanning IP:', error);
    return c.json({ error: 'Failed to unban IP' }, 500);
  }
});

// ── AREDL Sync ───────────────────────────────────────

app.post('/api/aredl-sync', authenticateToken, async (c) => {
  try {
    const response = await fetch('https://api.aredl.net/v2/api/aredl/levels');
    if (!response.ok) throw new Error('Failed to fetch AREDL data');
    const aredlLevels = await response.json() as any[];

    const currentLevels = await c.env.DB.prepare(`SELECT id, name, aredl_rank as aredlRank FROM levels`).all();
    const levelMap = new Map<string, { id: string; name: string; oldRank: number | null }>();
    for (const level of (currentLevels.results || [])) {
      levelMap.set((level as any).name.toLowerCase().trim(), {
        id: (level as any).id, name: (level as any).name, oldRank: (level as any).aredlRank,
      });
    }

    const aredlDataMap = new Map<string, any>();
    for (const aredlLevel of aredlLevels) {
      const name = aredlLevel.name?.toLowerCase().trim();
      if (name) aredlDataMap.set(name, aredlLevel);
    }

    const updates: { id: string; name: string; oldRank: number | null; newRank: number }[] = [];

    for (const [name, levelInfo] of levelMap) {
      const aredlData = aredlDataMap.get(name);
      if (aredlData) {
        const newRank = aredlData.position || aredlData.rank;
        await c.env.DB.prepare(`
          UPDATE levels SET aredl_rank = ?, edel_enjoyment = ?, nlw_tier = ?, gddl_tier = ? WHERE id = ?
        `).bind(newRank, aredlData.edel_enjoyment ?? null, aredlData.nlw_tier ?? null, aredlData.gddl_tier ?? null, levelInfo.id).run();
        updates.push({ id: levelInfo.id, name: levelInfo.name, oldRank: levelInfo.oldRank, newRank });
      }
    }

    const sortedLevels = await c.env.DB.prepare(
      'SELECT id FROM levels WHERE aredl_rank IS NOT NULL ORDER BY aredl_rank ASC'
    ).all();
    let hkgdRank = 1;
    for (const level of (sortedLevels.results || [])) {
      await c.env.DB.prepare('UPDATE levels SET hkgd_rank = ? WHERE id = ?').bind(hkgdRank, (level as any).id).run();
      hkgdRank++;
    }

    const unrankedLevels = await c.env.DB.prepare(
      'SELECT id FROM levels WHERE aredl_rank IS NULL ORDER BY hkgd_rank ASC'
    ).all();
    for (const level of (unrankedLevels.results || [])) {
      await c.env.DB.prepare('UPDATE levels SET hkgd_rank = ? WHERE id = ?').bind(hkgdRank, (level as any).id).run();
      hkgdRank++;
    }

    const today = new Date();
    const dateStr = `${today.getFullYear().toString().slice(-2)}/${String(today.getMonth() + 1).padStart(2, '0')}/${String(today.getDate()).padStart(2, '0')}`;
    await c.env.DB.prepare(`
      INSERT INTO changelog (id, date, level_name, level_id, change_type, description, list_type)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(`sync-${Date.now()}`, dateStr, 'AREDL Sync', 'system', 'sync', `AREDL sync completed. Updated ${updates.length} level rankings.`, 'classic').run();

    notifyContentChanged(c.env);
    return c.json({ success: true, message: `Synced ${updates.length} levels with AREDL`, updatedLevels: updates.length, details: updates.slice(0, 10) });
  } catch (error) {
    console.error('AREDL sync error:', error);
    return c.json({ error: 'Failed to sync with AREDL', details: error instanceof Error ? error.message : 'Unknown error' }, 500);
  }
});

// ── Google Sheets Sync ───────────────────────────────

app.post('/api/google-sheets/sync', authenticateToken, async (c) => {
  try {
    const apiKey = c.env.GOOGLE_SHEETS_API_KEY;
    const spreadsheetId = c.env.GOOGLE_SHEET_ID;
    const sheetRange = c.env.GOOGLE_SHEET_RANGE || "'Classic Demon'!A1:GX2000";
    if (!apiKey || !spreadsheetId) return c.json({ error: 'Google Sheets not configured' }, 500);

    const url = `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${encodeURIComponent(sheetRange)}?key=${apiKey}`;
    const response = await fetch(url);
    if (!response.ok) return c.json({ error: 'Failed to fetch sheet data', details: await response.text() }, 500);
    const rows = (await response.json() as any).values || [];
    if (rows.length < 2) return c.json({ error: 'No data found' }, 400);

    const existingLevels = await c.env.DB.prepare('SELECT id, level_id as gameId, name, aredl_rank as aredlRank FROM levels').all();
    const levelByGameId = new Map<string, any>();
    const existingNames = new Set<string>();
    for (const l of (existingLevels.results || [])) {
      const gameId = (l as any).gameId;
      if (gameId) levelByGameId.set(gameId, l);
      if ((l as any).name) existingNames.add((l as any).name.toLowerCase());
    }

    const allRecords = await c.env.DB.prepare('SELECT level_id, player, date FROM records').all();
    const existingRecordSet = new Set((allRecords.results || []).map((r: any) => `${r.level_id}|${r.player}|${r.date}`));

    const now = new Date().toISOString();
    let addedLevels = 0, addedRecords = 0;
    const levelsToInsert: any[] = [];
    const recordsToInsert: any[] = [];

    for (const row of rows.slice(1)) {
      if (row.length < 5) continue;
      const placement = row[0]?.toString().trim();
      const gameId = row[2]?.toString().trim();
      const levelName = row[3]?.toString().trim();
      if (!gameId || !levelName) continue;
      const victorsRaw = row[4]?.toString().trim();
      if (!victorsRaw || !/^\d+$/.test(victorsRaw) || parseInt(victorsRaw, 10) < 1) continue;
      if (existingNames.has(levelName.toLowerCase())) continue;

      const aredlRank = placement && !isNaN(Number(placement)) ? parseInt(placement) : null;
      const existing = levelByGameId.get(gameId);
      const dbId = existing ? (existing as any).id : gameId;

      if (!existing) {
        levelsToInsert.push({ id: gameId, gameId, name: levelName, aredlRank });
        addedLevels++;
      }

      for (let pi = 0; pi < 50; pi++) {
        const base = 5 + pi * 4;
        if (base >= row.length) break;
        const date = row[base]?.toString().trim();
        const player = row[base + 1]?.toString().trim();
        if (!date || !player) continue;
        const video = (base + 2 < row.length) ? row[base + 2]?.toString().trim() : '';
        const fpsRaw = (base + 3 < row.length) ? row[base + 3]?.toString().trim() : '';
        if (!existingRecordSet.has(`${dbId}|${player}|${date}`)) {
          const fps = fpsRaw && fpsRaw !== '/' ? parseInt(fpsRaw.replace(/[^0-9]/g, '')) || null : null;
          const videoUrl = video && video !== '/' && video.length > 0 ? video : null;
          recordsToInsert.push({ levelId: dbId, player, date, videoUrl, fps });
          existingRecordSet.add(`${dbId}|${player}|${date}`);
          addedRecords++;
        }
      }
    }

    const insertStmts = levelsToInsert.map(l => c.env.DB.prepare(`
      INSERT OR IGNORE INTO levels (id, hkgd_rank, aredl_rank, name, creator, verifier, level_id, tags, date_added)
      VALUES (?, 0, ?, ?, '', '', ?, ?, ?)
    `).bind(l.id, l.aredlRank, l.name, l.gameId, JSON.stringify(l.aredlRank ? ['Overall'] : []), now));
    if (insertStmts.length) await c.env.DB.batch(insertStmts);

    const BATCH_SIZE = 80;
    for (let i = 0; i < recordsToInsert.length; i += BATCH_SIZE) {
      const chunk = recordsToInsert.slice(i, i + BATCH_SIZE);
      const stmts = chunk.map(r => c.env.DB.prepare(`
        INSERT INTO records (level_id, player, date, video_url, fps, cbf, attempts)
        VALUES (?, ?, ?, ?, ?, 0, NULL)
      `).bind(r.levelId, r.player, r.date, r.videoUrl, r.fps));
      try { await c.env.DB.batch(stmts); } catch {
        for (const r of chunk) {
          try { await c.env.DB.prepare(`
            INSERT INTO records (level_id, player, date, video_url, fps, cbf, attempts)
            VALUES (?, ?, ?, ?, ?, 0, NULL)
          `).bind(r.levelId, r.player, r.date, r.videoUrl, r.fps).run(); } catch {}
        }
      }
    }

    const d = new Date();
    const dateStr = `${d.getFullYear().toString().slice(-2)}/${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}`;
    await c.env.DB.prepare(`
      INSERT INTO changelog (id, date, level_name, level_id, change_type, description, list_type)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(`gsheet-${Date.now()}`, dateStr, 'Google Sheets Sync', 'system', 'sync',
      `Added ${addedLevels} levels · Added ${addedRecords} records`, 'classic').run();

    return c.json({ success: true, message: `Synced: ${addedLevels} levels, ${addedRecords} records`, addedLevels, addedRecords });
  } catch (error) {
    console.error('Google Sheets sync error:', error);
    return c.json({ error: 'Sync failed', details: error instanceof Error ? error.message : String(error) }, 500);
  }
});

// ── Sync Level Details ───────────────────────────────

app.post('/api/levels/sync-details', authenticateToken, async (c) => {
  try {
    const levels = await c.env.DB.prepare(`
      SELECT id, level_id, name, creator, verifier, thumbnail, song_id, song_name
      FROM levels
      WHERE aredl_rank IS NOT NULL
      ORDER BY hkgd_rank ASC
      LIMIT 50
    `).all();

    const levelList = levels.results || [];
    const updates: any[] = [];

    for (const level of levelList) {
      try {
        const response = await fetch(
          `https://history.geometrydash.eu/api/v1/search/level/advanced/?query=${level.level_id}&limit=1&filter=online_id%3D${level.level_id}`
        );
        if (response.ok) {
          const data = await response.json() as any;
          const hit = data.hits?.[0];
          if (hit) {
            const updatesObj: any = {};
            if (hit.cache_username && hit.cache_username !== level.creator) updatesObj.creator = hit.cache_username;
            const newThumbnail = hit.cache_level_string_available
              ? `https://levelthumbs.prevter.me/thumbnail/${level.level_id}` : null;
            if (newThumbnail && newThumbnail !== level.thumbnail) updatesObj.thumbnail = newThumbnail;
            if (hit.cache_song_id && hit.cache_song_id !== level.song_id?.toString()) updatesObj.song_id = hit.cache_song_id.toString();

            if (Object.keys(updatesObj).length > 0) {
              const setClause = Object.keys(updatesObj).map(k => `${k} = ?`).join(', ');
              await c.env.DB.prepare(`UPDATE levels SET ${setClause} WHERE id = ?`).bind(...Object.values(updatesObj), level.id).run();
              updates.push({ id: level.id, name: level.name, changes: updatesObj });
            }
          }
        }
        await new Promise(r => setTimeout(r, 20));
      } catch (err) {
        console.error(`Failed to fetch ${level.name}:`, err);
      }
    }

    return c.json({ success: true, message: `Synced details for ${updates.length} levels`, updatedLevels: updates.length, details: updates.slice(0, 10) });
  } catch (error) {
    console.error('Level details sync error:', error);
    return c.json({ error: 'Failed to sync level details', details: error instanceof Error ? error.message : 'Unknown error' }, 500);
  }
});

// ── Suggestions ──────────────────────────────────────

app.get('/api/suggestions', async (c) => {
  try {
    const suggestions = await c.env.DB.prepare(`
      SELECT id, type, title, description, level_id as levelId, level_name as levelName,
        submitted_by as submittedBy, submitted_at as submittedAt, status,
        admin_notes as adminNotes, resolved_at as resolvedAt, resolved_by as resolvedBy
      FROM suggestions ORDER BY submitted_at DESC
    `).all();
    return c.json(suggestions.results || []);
  } catch (error) {
    console.error('Error fetching suggestions:', error);
    return c.json({ error: 'Failed to fetch suggestions' }, 500);
  }
});

app.get('/api/suggestions/pending', async (c) => {
  try {
    const suggestions = await c.env.DB.prepare(`
      SELECT id, type, title, description, level_id as levelId, level_name as levelName,
        submitted_by as submittedBy, submitted_at as submittedAt, status,
        admin_notes as adminNotes, resolved_at as resolvedAt, resolved_by as resolvedBy
      FROM suggestions WHERE status = 'pending' ORDER BY submitted_at DESC
    `).all();
    return c.json(suggestions.results || []);
  } catch (error) {
    console.error('Error fetching pending suggestions:', error);
    return c.json({ error: 'Failed to fetch pending suggestions' }, 500);
  }
});

app.post('/api/suggestions', async (c) => {
  try {
    const { type, title, description, levelId, levelName, submittedBy } = await c.req.json();
    const id = `suggestion-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const submittedAt = new Date().toISOString();
    await c.env.DB.prepare(`
      INSERT INTO suggestions (id, type, title, description, level_id, level_name, submitted_by, submitted_at, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    `).bind(id, type || 'issue', title, description, levelId || null, levelName || null, submittedBy || null, submittedAt).run();
    return c.json({ success: true, id, message: 'Suggestion submitted successfully' }, 201);
  } catch (error) {
    console.error('Error creating suggestion:', error);
    return c.json({ error: 'Failed to submit suggestion' }, 500);
  }
});

app.put('/api/suggestions/:id', authenticateToken, async (c: any) => {
  try {
    const id = c.req.param('id');
    const { status, adminNotes } = await c.req.json();
    if (!['pending', 'approved', 'rejected', 'fixed', 'in_progress'].includes(status)) return c.json({ error: 'Invalid status' }, 400);
    const resolvedAt = status !== 'pending' ? new Date().toISOString() : null;
    const user = c.get('user') as any;
    const resolvedBy = status !== 'pending' ? (user.isAdmin === true ? 'admin' : 'suggestions_admin') : null;
    await c.env.DB.prepare('UPDATE suggestions SET status = ?, admin_notes = ?, resolved_at = ?, resolved_by = ? WHERE id = ?')
      .bind(status, adminNotes || null, resolvedAt, resolvedBy, id).run();
    return c.json({ success: true, message: 'Suggestion updated successfully' });
  } catch (error) {
    console.error('Error updating suggestion:', error);
    return c.json({ error: 'Failed to update suggestion' }, 500);
  }
});

app.delete('/api/suggestions/:id', authenticateToken, async (c) => {
  try {
    await c.env.DB.prepare('DELETE FROM suggestions WHERE id = ?').bind(c.req.param('id')).run();
    return c.json({ success: true, message: 'Suggestion deleted successfully' });
  } catch (error) {
    console.error('Error deleting suggestion:', error);
    return c.json({ error: 'Failed to delete suggestion' }, 500);
  }
});

// ── Platformer Levels CRUD ───────────────────────────

app.get('/api/platformer-levels', async (c) => {
  try {
    const levels = await c.env.DB.prepare(`
      SELECT id, hkgd_rank as hkgdRank, name, creator, verifier, level_id as levelId,
        description, thumbnail, song_id as songId, song_name as songName, tags,
        date_added as dateAdded, pack, difficulty
      FROM platformer_levels ORDER BY hkgd_rank ASC
    `).all();

    const allRecords = await c.env.DB.prepare(`
      SELECT id, level_id, player, date, video_url as videoUrl, fps, cbf, attempts, points
      FROM platformer_records ORDER BY date DESC
    `).all();

    const recordsByLevel: Record<string, any[]> = {};
    for (const r of (allRecords.results || [])) {
      if (!recordsByLevel[r.level_id as string]) recordsByLevel[r.level_id as string] = [];
      recordsByLevel[r.level_id as string].push({ ...r, cbf: r.cbf === 1 });
    }

    return c.json((levels.results || []).map((level: any) => ({
      ...level,
      tags: level.tags ? JSON.parse(level.tags) : [],
      records: recordsByLevel[level.id] || [],
    })));
  } catch (error) {
    console.error('Error fetching platformer levels:', error);
    return c.json({ error: 'Failed to fetch platformer levels' }, 500);
  }
});

app.get('/api/platformer-levels/:id', async (c) => {
  try {
    const level = await c.env.DB.prepare(`
      SELECT id, hkgd_rank as hkgdRank, name, creator, verifier, level_id as levelId,
        description, thumbnail, song_id as songId, song_name as songName, tags,
        date_added as dateAdded, pack, difficulty
      FROM platformer_levels WHERE id = ?
    `).bind(c.req.param('id')).first();

    if (!level) return c.json({ error: 'Platformer level not found' }, 404);

    const records = await c.env.DB.prepare(`
      SELECT id, player, date, video_url as videoUrl, fps, cbf, attempts, points
      FROM platformer_records WHERE level_id = ? ORDER BY date DESC
    `).bind(c.req.param('id')).all();

    return c.json({
      ...level,
      tags: (level.tags as string) ? JSON.parse(level.tags as string) : [],
      records: (records.results || []).map((r: any) => ({ ...r, cbf: r.cbf === 1 })),
    });
  } catch (error) {
    console.error('Error fetching platformer level:', error);
    return c.json({ error: 'Failed to fetch platformer level' }, 500);
  }
});

app.post('/api/platformer-levels', authenticateToken, async (c) => {
  try {
    const data = await c.req.json();
    const { id, hkgdRank, name, creator, verifier, levelId, description, thumbnail, songId, songName, tags, dateAdded, pack, difficulty } = data;
    await c.env.DB.prepare(`
      INSERT INTO platformer_levels (id, hkgd_rank, name, creator, verifier, level_id, description, thumbnail, song_id, song_name, tags, date_added, pack, difficulty)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(safe(id), safe(hkgdRank), safe(name), safe(creator), safe(verifier), safe(levelId),
      safe(description), safe(thumbnail), safe(songId), safe(songName),
      JSON.stringify(tags || []), safe(dateAdded), safe(pack), safe(difficulty)).run();
    notifyContentChanged(c.env);
    return c.json({ id, message: 'Platformer level created successfully' }, 201);
  } catch (error) {
    console.error('Error creating platformer level:', error);
    return c.json({ error: 'Failed to create platformer level', details: error instanceof Error ? error.message : 'Unknown error' }, 500);
  }
});

app.put('/api/platformer-levels/:id', authenticateToken, async (c) => {
  try {
    const data = await c.req.json();
    const { hkgdRank, name, creator, verifier, levelId, description, thumbnail, songId, songName, tags, dateAdded, pack, difficulty } = data;
    await c.env.DB.prepare(`
      UPDATE platformer_levels SET hkgd_rank = ?, name = ?, creator = ?, verifier = ?, level_id = ?,
        description = ?, thumbnail = ?, song_id = ?, song_name = ?, tags = ?, date_added = ?, pack = ?, difficulty = ?
      WHERE id = ?
    `).bind(safe(hkgdRank), safe(name), safe(creator), safe(verifier), safe(levelId),
      safe(description), safe(thumbnail), safe(songId), safe(songName),
      JSON.stringify(tags || []), safe(dateAdded), safe(pack), safe(difficulty), c.req.param('id')).run();
    notifyContentChanged(c.env);
    return c.json({ message: 'Platformer level updated successfully' });
  } catch (error) {
    console.error('Error updating platformer level:', error);
    return c.json({ error: 'Failed to update platformer level' }, 500);
  }
});

app.delete('/api/platformer-levels/:id', authenticateToken, async (c) => {
  try {
    await c.env.DB.prepare('DELETE FROM platformer_levels WHERE id = ?').bind(c.req.param('id')).run();
    notifyContentChanged(c.env);
    return c.json({ message: 'Platformer level deleted successfully' });
  } catch (error) {
    console.error('Error deleting platformer level:', error);
    return c.json({ error: 'Failed to delete platformer level' }, 500);
  }
});

// ── Platformer Records ───────────────────────────────

app.post('/api/platformer-levels/:levelId/records', authenticateToken, async (c) => {
  try {
    const body = await c.req.json();
    let points: number | null = null;
    const level = await c.env.DB.prepare('SELECT id, hkgd_rank FROM platformer_levels WHERE id = ?').bind(c.req.param('levelId')).first();
    if (level && (level as any).hkgd_rank) {
      const totalLevelsResult = await c.env.DB.prepare('SELECT COUNT(*) as count FROM platformer_levels WHERE hkgd_rank IS NOT NULL').first();
      points = computePoints((level as any).hkgd_rank, (totalLevelsResult as any)?.count || 0);
    }

    const result = await c.env.DB.prepare(`
      INSERT INTO platformer_records (level_id, player, date, video_url, fps, cbf, attempts, points)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(c.req.param('levelId'), safe(body.player), safe(body.date), safe(body.videoUrl || body.video_url),
      safe(body.fps), body.cbf ? 1 : 0, safe(body.attempts), safe(points)).run();

    notifyContentChanged(c.env);
    return c.json({ message: 'Platformer record added successfully', id: result.meta.last_row_id, points }, 201);
  } catch (error) {
    console.error('Error adding platformer record:', error);
    return c.json({ error: 'Failed to add platformer record' }, 500);
  }
});

app.put('/api/platformer-records/:recordId', authenticateToken, async (c) => {
  try {
    const data = await c.req.json();
    const recordId = c.req.param('recordId');
    const updates: string[] = [];
    const values: any[] = [];
    const fields = ['player', 'date', 'video_url', 'fps', 'cbf', 'attempts', 'points'];
    const dataMap: any = { player: data.player, date: data.date, video_url: data.videoUrl, fps: data.fps, cbf: data.cbf ? 1 : 0, attempts: data.attempts, points: data.points };
    for (const field of fields) { if (dataMap[field] !== undefined) { updates.push(`${field} = ?`); values.push(dataMap[field]); } }
    if (updates.length === 0) return c.json({ error: 'No fields to update' }, 400);
    values.push(parseInt(recordId));
    const result = await c.env.DB.prepare(`UPDATE platformer_records SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
    if (result.meta.changes === 0) return c.json({ error: 'Platformer record not found' }, 404);
    return c.json({ message: 'Platformer record updated successfully' });
  } catch (error) {
    console.error('Error updating platformer record:', error);
    return c.json({ error: 'Failed to update platformer record', details: error instanceof Error ? error.message : 'Unknown error' }, 500);
  }
});

app.delete('/api/platformer-records/:recordId', authenticateToken, async (c) => {
  try {
    const recordId = parseInt(c.req.param('recordId'));
    const result = await c.env.DB.prepare('DELETE FROM platformer_records WHERE id = ?').bind(recordId).run();
    if (result.meta.changes === 0) return c.json({ error: 'Platformer record not found' }, 404);
    return c.json({ message: 'Platformer record deleted successfully' });
  } catch (error) {
    console.error('Error deleting platformer record:', error);
    return c.json({ error: 'Failed to delete platformer record' }, 500);
  }
});

// ── Platformer Sync Details ──────────────────────────

app.post('/api/platformer-levels/sync-details', authenticateToken, async (c) => {
  try {
    const levels = await c.env.DB.prepare(`
      SELECT id, level_id, name, creator, verifier, thumbnail, song_id, song_name
      FROM platformer_levels ORDER BY hkgd_rank ASC LIMIT 30
    `).all();
    const updates: any[] = [];
    for (const level of (levels.results || [])) {
      try {
        const response = await fetch(`https://history.geometrydash.eu/api/v1/search/level/advanced/?query=${level.level_id}&limit=1&filter=online_id%3D${level.level_id}`);
        if (response.ok) {
          const data = await response.json() as any;
          const hit = data.hits?.[0];
          if (hit) {
            const updatesObj: any = {};
            if (hit.cache_username && hit.cache_username !== level.creator) updatesObj.creator = hit.cache_username;
            const newThumbnail = hit.cache_level_string_available ? `https://levelthumbs.prevter.me/thumbnail/${level.level_id}` : null;
            if (newThumbnail && newThumbnail !== level.thumbnail) updatesObj.thumbnail = newThumbnail;
            if (hit.cache_song_id && hit.cache_song_id !== level.song_id?.toString()) updatesObj.song_id = hit.cache_song_id.toString();
            if (Object.keys(updatesObj).length > 0) {
              const setClause = Object.keys(updatesObj).map(k => `${k} = ?`).join(', ');
              await c.env.DB.prepare(`UPDATE platformer_levels SET ${setClause} WHERE id = ?`).bind(...Object.values(updatesObj), level.id).run();
              updates.push({ id: level.id, name: level.name, changes: updatesObj });
            }
          }
        }
        await new Promise(r => setTimeout(r, 20));
      } catch (err) { console.error(`Failed to fetch ${level.name}:`, err); }
    }
    return c.json({ success: true, message: `Synced details for ${updates.length} platformer levels`, updatedLevels: updates.length, details: updates.slice(0, 10) });
  } catch (error) {
    console.error('Platformer level details sync error:', error);
    return c.json({ error: 'Failed to sync platformer level details', details: error instanceof Error ? error.message : 'Unknown error' }, 500);
  }
});

// ── Bulk Import Platformer Levels ────────────────────

app.post('/api/platformer-levels/bulk-import', authenticateToken, async (c) => {
  try {
    const levels = await c.req.json();
    if (!Array.isArray(levels)) return c.json({ error: 'Expected array of levels' }, 400);
    const results: any[] = [];
    const errors: string[] = [];

    for (const levelData of levels) {
      try {
        const { name, levelId, hkgdRank, creator, records } = levelData;
        const id = `plat-${levelId}`;
        const existing = await c.env.DB.prepare('SELECT id FROM platformer_levels WHERE id = ?').bind(id).first();
        if (existing) { results.push({ name, status: 'skipped', reason: 'already exists' }); continue; }

        let details: any = null;
        try {
          const response = await fetch(`https://history.geometrydash.eu/api/v1/search/level/advanced/?query=${levelId}&limit=1&filter=online_id%3D${levelId}`);
          if (response.ok) details = ((await response.json()) as any).hits?.[0];
        } catch {}

        await c.env.DB.prepare(`
          INSERT INTO platformer_levels (id, hkgd_rank, name, creator, verifier, level_id, thumbnail, tags, date_added)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(id, hkgdRank, details?.cache_level_name || name, details?.cache_username || creator || 'Unknown',
          details?.cache_username || creator || 'Unknown', levelId,
          details?.cache_level_string_available ? `https://levelthumbs.prevter.me/thumbnail/${levelId}` : null,
          JSON.stringify(['Platformer']), new Date().toISOString()).run();

        if (records && Array.isArray(records)) {
          for (const record of records) {
            await c.env.DB.prepare(`
              INSERT INTO platformer_records (id, level_id, player, date, video_url, fps, cbf)
              VALUES (?, ?, ?, ?, ?, ?, ?)
            `).bind(`plat-rec-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`, id, record.player, record.date, record.videoUrl || null, record.fps || 60, record.cbf || false).run();
          }
        }
        results.push({ name, status: 'added', hkgdRank });
      } catch (err) { errors.push(`${levelData.name}: ${err instanceof Error ? err.message : 'Unknown error'}`); }
    }
    return c.json({ success: true, message: `Imported ${results.filter(r => r.status === 'added').length} levels`, results: results.slice(0, 20), errors: errors.slice(0, 10) });
  } catch (error) {
    console.error('Bulk import error:', error);
    return c.json({ error: 'Failed to bulk import', details: error instanceof Error ? error.message : 'Unknown error' }, 500);
  }
});

// ── Platformer Level Sync (AREDL-style, manual trigger) ──

app.post('/api/platformer-levels/sync', authenticateToken, async (c) => {
  try {
    const levels = await c.env.DB.prepare('SELECT id, level_id, name, hkgd_rank FROM platformer_levels ORDER BY hkgd_rank ASC').all();
    let updated = 0;
    for (const level of (levels.results || [])) {
      try {
        const response = await fetch(`https://history.geometrydash.eu/api/v1/search/level/advanced/?query=${level.level_id}&limit=1&filter=online_id%3D${level.level_id}`);
        if (response.ok) {
          const data = await response.json() as any;
          const hit = data.hits?.[0];
          if (hit) {
            await c.env.DB.prepare(`UPDATE platformer_levels SET name = ?, creator = ?, verifier = ?, thumbnail = ?, song_id = ?, song_name = ? WHERE id = ?`)
              .bind(hit.cache_level_name || level.name, hit.cache_username || 'Unknown', hit.cache_username || 'Unknown',
                hit.cache_level_string_available ? `https://levelthumbs.prevter.me/thumbnail/${level.level_id}` : null,
                hit.cache_song_id?.toString() || null, null, level.id).run();
            updated++;
          }
        }
        await new Promise(r => setTimeout(r, 20));
      } catch {}
    }
    return c.json({ success: true, message: `Synced ${updated} platformer levels` });
  } catch (error) {
    console.error('Platformer sync error:', error);
    return c.json({ error: 'Failed to sync platformer levels' }, 500);
  }
});

// ── MOTD ─────────────────────────────────────────────

const MAP_TYPE_PATTERNS: Record<string, RegExp> = {
  daily: /MOTD Map \d+/,
  weekly: /MOTW Map \d+/,
  monthly: /MOTM Map \d+/,
  platformer: /PLATFORMER MOTD Map \d+/,
  curve: /CURVE MAP #?\d+/,
};

async function syncMotdFromDiscord(env: Bindings): Promise<Record<string, { levelId: string; message: string }> | null> {
  const botToken = env.DISCORD_BOT_TOKEN;
  const channelId = env.DISCORD_CHANNEL_ID;
  if (!botToken || !channelId) return null;
  try {
    const response = await fetch(`https://discord.com/api/v10/channels/${channelId}/messages?limit=50`, {
      headers: { Authorization: `Bot ${botToken}` },
    });
    if (!response.ok) return null;
    const messages = await response.json() as any[];
    if (!messages?.length) return null;
    const found: Record<string, { levelId: string; message: string }> = {};
    for (const msg of messages) {
      const content = msg.content;
      if (!content) continue;
      const idMatch = content.match(/ID:\s*(\d+)/);
      if (!idMatch) continue;
      for (const [type, pattern] of Object.entries(MAP_TYPE_PATTERNS)) {
        if (pattern.test(content) && !found[type]) {
          found[type] = { levelId: idMatch[1], message: content };
          break;
        }
      }
    }
    return Object.keys(found).length > 0 ? found : null;
  } catch { return null; }
}

app.post('/api/motd/sync-from-discord', authenticateToken, async (c: any) => {
  try {
    const results = await syncMotdFromDiscord(c.env);
    if (!results) {
      return c.json({ error: 'Discord sync failed — no matching map messages found' }, 500);
    }

    const updatedAt = new Date().toISOString();
    const stored: Record<string, string> = {};

    for (const [type, data] of Object.entries(results)) {
      await c.env.DB.prepare(`
        INSERT INTO motd (id, message, updated_at, updated_by)
        VALUES (?, ?, ?, 'discord-bot')
        ON CONFLICT(id) DO UPDATE SET
          message = excluded.message,
          updated_at = excluded.updated_at,
          updated_by = excluded.updated_by
      `).bind(type, data.message, updatedAt).run();
      stored[type] = data.levelId;
    }

    return c.json({ success: true, types: stored });
  } catch (error) {
    console.error('Error syncing MOTD from Discord:', error);
    return c.json({ error: 'Failed to sync MOTD from Discord' }, 500);
  }
});

app.get('/api/motd', async (c) => {
  try {
    const type = c.req.query('type') || null;
    if (type) {
      const row = await c.env.DB.prepare("SELECT message FROM motd WHERE id = ?").bind(type).first();
      return c.json({ message: row?.message || '', type });
    }
    const rows = await c.env.DB.prepare("SELECT id, message FROM motd WHERE id != 'main' ORDER BY id").all();
    const messages: Record<string, string> = {};
    for (const row of rows.results) {
      messages[(row as any).id] = (row as any).message;
    }
    return c.json({ messages, types: Object.keys(messages) });
  } catch (error) {
    console.error('Error fetching MOTD:', error);
    return c.json({ message: '' });
  }
});

app.put('/api/motd', authenticateToken, async (c: any) => {
  try {
    const { message, type } = await c.req.json();
    const mapType = type || 'main';
    const updatedAt = new Date().toISOString();
    const user = c.get('user') as any;
    const updatedBy = user?.isAdmin === true ? 'admin' : 'suggestions';
    await c.env.DB.prepare(`
      INSERT INTO motd (id, message, updated_at, updated_by)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        message = excluded.message,
        updated_at = excluded.updated_at,
        updated_by = excluded.updated_by
    `).bind(mapType, message, updatedAt, updatedBy).run();

    return c.json({ message, updatedAt, updatedBy, type: mapType });
  } catch (error) {
    console.error('Error updating MOTD:', error);
    return c.json({ error: 'Failed to update MOTD' }, 500);
  }
});

// ── Health ───────────────────────────────────────────

app.get('/api/health', (c) => c.json({ status: 'ok', timestamp: new Date().toISOString() }));

// ── Export ───────────────────────────────────────────

export default {
  fetch: app.fetch,
  scheduled: async (controller: any, env: any, ctx: any) => {
    if (controller.cron === '0 18 * * *') {
      console.log('[Cron] Starting MOTD sync from Discord...');
      const results = await syncMotdFromDiscord(env);
      if (results) {
        const updatedAt = new Date().toISOString();
        for (const [type, data] of Object.entries(results)) {
          await env.DB.prepare(`
            INSERT INTO motd (id, message, updated_at, updated_by)
            VALUES (?, ?, ?, 'discord-bot')
            ON CONFLICT(id) DO UPDATE SET
              message = excluded.message,
              updated_at = excluded.updated_at,
              updated_by = excluded.updated_by
          `).bind(type, data.message, updatedAt).run();
          console.log(`[Cron] MOTD ${type} synced to level ID ${data.levelId}`);
        }
      } else {
        console.error('[Cron] MOTD sync failed');
      }
      return;
    }

    const response = await fetch('https://api.aredl.net/v2/api/aredl/levels');
    if (!response.ok) { console.error('AREDL sync failed'); return; }
    const aredlLevels = await response.json() as any[];
    const currentLevels = await env.DB.prepare('SELECT id, name, aredl_rank as aredlRank FROM levels').all();
    const levelMap = new Map<string, { id: string; name: string; oldRank: number | null }>();
    for (const level of (currentLevels.results || [])) {
      levelMap.set((level as any).name.toLowerCase().trim(), { id: (level as any).id, name: (level as any).name, oldRank: (level as any).aredlRank });
    }
    const aredlDataMap = new Map<string, any>();
    for (const aredlLevel of aredlLevels) { const n = aredlLevel.name?.toLowerCase().trim(); if (n) aredlDataMap.set(n, aredlLevel); }
    let updatedCount = 0;
    for (const [name, levelInfo] of levelMap) {
      const aredlData = aredlDataMap.get(name);
      if (aredlData) {
        await env.DB.prepare('UPDATE levels SET aredl_rank = ?, edel_enjoyment = ?, nlw_tier = ?, gddl_tier = ? WHERE id = ?')
          .bind(aredlData.position || aredlData.rank, aredlData.edel_enjoyment ?? null, aredlData.nlw_tier ?? null, aredlData.gddl_tier ?? null, levelInfo.id).run();
        updatedCount++;
      }
    }
    const sortedLevels = await env.DB.prepare('SELECT id FROM levels WHERE aredl_rank IS NOT NULL ORDER BY aredl_rank ASC').all();
    let hkgdRank = 1;
    for (const level of (sortedLevels.results || [])) { await env.DB.prepare('UPDATE levels SET hkgd_rank = ? WHERE id = ?').bind(hkgdRank, (level as any).id).run(); hkgdRank++; }
    const unrankedLevels = await env.DB.prepare('SELECT id FROM levels WHERE aredl_rank IS NULL ORDER BY hkgd_rank ASC').all();
    for (const level of (unrankedLevels.results || [])) { await env.DB.prepare('UPDATE levels SET hkgd_rank = ? WHERE id = ?').bind(hkgdRank, (level as any).id).run(); hkgdRank++; }
    console.log(`AREDL auto-sync completed: ${updatedCount} levels updated`);
  }
};
