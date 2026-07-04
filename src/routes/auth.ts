import { Hono } from 'hono';
import { SignJWT } from 'jose';
import bcrypt from 'bcryptjs';
import { Bindings, safe } from '../types';
import { authenticateToken, authenticateUser, createUserJwt } from '../helpers/auth';
import { getClientIP, createNotification } from '../helpers/utils';
import { sendPasswordResetEmail } from '../helpers/email';
import { isIPBanned, recordFailedLogin, resetFailedAttempts, MAX_LOGIN_ATTEMPTS } from '../helpers/ipban';

const BCRYPT_ROUNDS = 10;

export function registerAuthRoutes(app: Hono<{ Bindings: Bindings }>) {
  // ── Admin Auth ───────────────────────────────────────

  app.post('/api/auth/login', async (c) => {
    try {
      const { password } = await c.req.json();
      const ip = getClientIP(c);
      const jwtSecret = c.env.JWT_SECRET;
      const motdPassword = c.env.MOTD_ADMIN_PASSWORD;

      if (!jwtSecret) {
        return c.json({ error: 'Server configuration error' }, 500);
      }

      const { banned, remainingTime } = await isIPBanned(c.env.DB, ip);
      if (banned) {
        return c.json({ error: 'IP banned', message: `Too many failed login attempts. Try again in ${Math.floor(remainingTime! / 60)} minutes.`, remainingTime }, 403);
      }

      let role: any = null;
      if (motdPassword && password === motdPassword) role = 'motd';

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

  // ── User Register ────────────────────────────────────

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
      const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

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

  // ── User Login ───────────────────────────────────────

  app.post('/api/user/login', async (c) => {
    try {
      const { username, password, rememberMe } = await c.req.json();
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

      const passwordMatch = await bcrypt.compare(password, (user as any).password);
      if (!passwordMatch) {
        await recordFailedLogin(c.env.DB, ip);
        return c.json({ error: 'Invalid username or password' }, 401);
      }

      await resetFailedAttempts(c.env.DB, ip);
      const token = await createUserJwt(user, c.env.JWT_SECRET, rememberMe);

      return c.json({
        success: true,
        token,
        user: {
          id: (user as any).id,
          username: (user as any).username,
          displayName: (user as any).display_name,
          playerName: (user as any).player_name,
          discord: (user as any).discord,
          email: (user as any).email,
          isAdmin: !!(user as any).is_admin,
        }
      });
    } catch (error) {
      console.error('User login error:', error);
      return c.json({ error: 'Login failed' }, 500);
    }
  });

  // ── User Profile ─────────────────────────────────────

  const PROFILE_FIELDS = 'id, username, display_name, player_name, discord, email, is_admin, created_at, updated_at';

  app.get('/api/user/profile', authenticateUser, async (c: any) => {
    try {
      const { userId } = c.get('user');
      const user = await c.env.DB.prepare(
        `SELECT ${PROFILE_FIELDS} FROM users WHERE id = ?`
      ).bind(userId).first();
      if (!user) return c.json({ error: 'User not found' }, 404);
      return c.json({
        id: user.id, username: user.username, displayName: user.display_name,
        playerName: user.player_name, discord: user.discord, email: user.email,
        isAdmin: !!user.is_admin, createdAt: user.created_at, updatedAt: user.updated_at,
      });
    } catch (error) {
      console.error('Profile error:', error);
      return c.json({ error: 'Failed to fetch profile' }, 500);
    }
  });

  app.get('/api/user/me', authenticateUser, async (c: any) => {
    const { userId } = c.get('user');
    const user = await c.env.DB.prepare(
      `SELECT ${PROFILE_FIELDS} FROM users WHERE id = ?`
    ).bind(userId).first();
    if (!user) return c.json({ error: 'User not found' }, 404);
    return c.json({
      id: user.id, username: user.username, displayName: user.display_name,
      playerName: user.player_name, discord: user.discord, email: user.email,
      isAdmin: !!user.is_admin, createdAt: user.created_at, updatedAt: user.updated_at,
    });
  });

  app.put('/api/user/profile', authenticateUser, async (c: any) => {
    try {
      const { userId } = c.get('user');
      const { displayName, playerName, email } = await c.req.json();

      if (email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) return c.json({ error: 'Invalid email format' }, 400);
        const existing = await c.env.DB.prepare('SELECT id FROM users WHERE email = ? AND id != ?').bind(email, userId).first();
        if (existing) return c.json({ error: 'Email already in use' }, 409);
      }

      const now = new Date().toISOString();
      await c.env.DB.prepare(`
        UPDATE users SET display_name = ?, player_name = ?, email = ?, updated_at = ?
        WHERE id = ?
      `).bind(safe(displayName), safe(playerName), safe(email), now, userId).run();

      return c.json({ success: true, message: 'Profile updated' });
    } catch (error) {
      console.error('Profile update error:', error);
      return c.json({ error: 'Failed to update profile' }, 500);
    }
  });

  // ── User Notifications ───────────────────────────────

  app.get('/api/user/notifications', authenticateUser, async (c: any) => {
    try {
      const { userId } = c.get('user');
      const notifications = await c.env.DB.prepare(`
        SELECT id, type, title, message, read, created_at
        FROM notifications WHERE user_id = ? ORDER BY created_at DESC
      `).bind(userId).all();

      return c.json((notifications.results || []).map((n: any) => ({
        id: n.id, type: n.type, title: n.title, message: n.message,
        read: n.read === 1, createdAt: n.created_at,
      })));
    } catch (error) {
      console.error('Notifications error:', error);
      return c.json({ error: 'Failed to fetch notifications' }, 500);
    }
  });

  app.get('/api/notifications', authenticateUser, async (c: any) => {
    try {
      const { userId } = c.get('user');
      const notifications = await c.env.DB.prepare(`
        SELECT id, type, title, message, read, created_at
        FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50
      `).bind(userId).all();

      const unread = (notifications.results || []).filter((n: any) => !n.read).length;
      return c.json({
        notifications: (notifications.results || []).map((n: any) => ({
          id: n.id, type: n.type, title: n.title, message: n.message, read: n.read, created_at: n.created_at,
        })),
        unreadCount: unread,
      });
    } catch (error) {
      console.error('Notifications error:', error);
      return c.json({ error: 'Failed to fetch notifications' }, 500);
    }
  });

  app.get('/api/user/records', authenticateUser, async (c: any) => {
    try {
      const { userId } = c.get('user');
      const user = await c.env.DB.prepare('SELECT player_name, username FROM users WHERE id = ?').bind(userId).first() as any;
      const names = [user?.player_name, user?.username].filter(Boolean);
      if (names.length === 0) return c.json([]);
      const placeholders = names.map(() => '?').join(', ');

      const records = await c.env.DB.prepare(`
        SELECT r.id, r.level_id, r.player, r.date, r.video_url, r.fps, r.cbf, r.attempts, r.points,
               l.name as level_name, l.hkgd_rank
        FROM records r
        JOIN levels l ON r.level_id = l.id
        WHERE LOWER(r.player) IN (${names.map(() => 'LOWER(?)').join(', ')})
        AND l.hkgd_rank > 0
        ORDER BY r.date DESC
      `).bind(...names).all();

      return c.json((records.results || []).map((r: any) => ({
        id: r.id, levelName: r.level_name, levelId: r.level_id, player: r.player,
        date: r.date, videoUrl: r.video_url, fps: r.fps, cbf: r.cbf, attempts: r.attempts, points: r.points,
      })));
    } catch (error) {
      console.error('User records error:', error);
      return c.json({ error: 'Failed to fetch records' }, 500);
    }
  });

  app.get('/api/user/submissions', authenticateUser, async (c: any) => {
    try {
      const { userId } = c.get('user');
      const user = await c.env.DB.prepare('SELECT player_name, username FROM users WHERE id = ?').bind(userId).first();
      const names = [(user as any)?.player_name, (user as any)?.username].filter(Boolean);
      if (names.length === 0) return c.json([]);
      const submissions = await c.env.DB.prepare(`
        SELECT id, level_name, status, admin_notes, submitted_at
        FROM pending_submissions
        WHERE submitted_by IN (${names.map(() => '?').join(', ')})
        ORDER BY submitted_at DESC
      `).bind(...names).all();

      return c.json((submissions.results || []).map((s: any) => ({
        id: s.id, levelName: s.level_name, status: s.status,
        adminNotes: s.admin_notes, submittedAt: s.submitted_at,
      })));
    } catch (error) {
      console.error('User submissions error:', error);
      return c.json({ error: 'Failed to fetch submissions' }, 500);
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
      await c.env.DB.prepare('UPDATE notifications SET read = 1 WHERE user_id = ?').bind(userId).run();
      return c.json({ success: true });
    } catch (error) {
      console.error('Read all error:', error);
      return c.json({ error: 'Failed to mark all as read' }, 500);
    }
  });

  app.put('/api/notifications/:id/read', authenticateUser, async (c: any) => {
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

  app.put('/api/notifications/read-all', authenticateUser, async (c: any) => {
    try {
      const { userId } = c.get('user');
      await c.env.DB.prepare('UPDATE notifications SET read = 1 WHERE user_id = ?').bind(userId).run();
      return c.json({ success: true });
    } catch (error) {
      console.error('Read all error:', error);
      return c.json({ error: 'Failed to mark all as read' }, 500);
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
      `).bind(tokenId, (user as any).id, token, expiresAt, now).run();

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

      const hashedPassword = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);

      await c.env.DB.prepare('UPDATE users SET password = ? WHERE id = ?')
        .bind(hashedPassword, (resetToken as any).user_id).run();

      await c.env.DB.prepare('UPDATE reset_tokens SET used = 1 WHERE id = ?')
        .bind((resetToken as any).id).run();

      return c.json({ success: true, message: 'Password reset successfully' });
    } catch (error) {
      console.error('Reset password error:', error);
      return c.json({ error: 'Failed to reset password' }, 500);
    }
  });

  // ── User Claims ──────────────────────────────────────

  app.get('/api/user/claims', authenticateUser, async (c: any) => {
    try {
      const { userId } = c.get('user');
      const claims = await c.env.DB.prepare(`
        SELECT id, player_name, level_id, level_name, record_date, status, created_at
        FROM claims WHERE user_id = ? ORDER BY created_at DESC
      `).bind(userId).all();

      return c.json((claims.results || []).map((cl: any) => ({
        id: cl.id, playerName: cl.player_name, levelId: cl.level_id,
        levelName: cl.level_name, recordDate: cl.record_date, status: cl.status, createdAt: cl.created_at,
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

  // ── Player Name Claims ───────────────────────────────

  app.get('/api/claims', authenticateUser, async (c: any) => {
    try {
      const { userId } = c.get('user');
      const claims = await c.env.DB.prepare(`
        SELECT id, player_name, status, created_at
        FROM claims WHERE user_id = ? AND player_name IS NOT NULL ORDER BY created_at DESC
      `).bind(userId).all();

      return c.json((claims.results || []).map((cl: any) => ({
        id: cl.id, player_name: cl.player_name, status: cl.status, created_at: cl.created_at,
      })));
    } catch (error) {
      console.error('Player claims error:', error);
      return c.json({ error: 'Failed to fetch claims' }, 500);
    }
  });

  app.post('/api/claims', authenticateUser, async (c: any) => {
    try {
      const { userId, username } = c.get('user');
      const { playerName } = await c.req.json();
      if (!playerName) return c.json({ error: 'playerName required' }, 400);

      const id = `claim-${crypto.randomUUID()}`;
      const now = new Date().toISOString();

      await c.env.DB.prepare(`
        INSERT INTO claims (id, user_id, player_name, level_id, level_name, status, created_at)
        VALUES (?, ?, ?, '', '', 'pending', ?)
      `).bind(id, userId, playerName, now).run();

      const admins = await c.env.DB.prepare("SELECT id FROM users WHERE username LIKE 'HKGDAdmin%'").all();
      for (const admin of (admins.results || [])) {
        await createNotification(c.env.DB, (admin as any).id, 'claim',
          `New player name claim from ${username}`,
          `${username} wants to claim player name "${playerName}"`
        );
      }

      return c.json({ success: true, id, message: 'Claim submitted' }, 201);
    } catch (error) {
      console.error('Create player claim error:', error);
      return c.json({ error: 'Failed to submit claim' }, 500);
    }
  });
}
