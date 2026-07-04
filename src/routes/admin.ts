import { Hono } from 'hono';
import bcrypt from 'bcryptjs';
import { Bindings, safe } from '../types';
import { authenticateToken } from '../helpers/auth';
import { createNotification } from '../helpers/utils';

const BCRYPT_ROUNDS = 10;

export function registerAdminRoutes(app: Hono<{ Bindings: Bindings }>) {
  // ── Admin: Users ─────────────────────────────────────

  app.get('/api/admin/users', authenticateToken, async (c: any) => {
    try {
      const { search } = c.req.query();
      let query = 'SELECT id, username, display_name, player_name, discord, email, is_admin, created_at FROM users';
      const params: any[] = [];
      if (search) {
        query += ' WHERE username LIKE ? OR display_name LIKE ? OR player_name LIKE ? OR email LIKE ?';
        const s = `%${search}%`;
        params.push(s, s, s, s);
      }
      query += ' ORDER BY created_at DESC';

      const users = await c.env.DB.prepare(query).bind(...params).all();
      return c.json((users.results || []).map((u: any) => ({
        id: u.id, username: u.username, displayName: u.display_name, playerName: u.player_name,
        discord: u.discord, email: u.email, isAdmin: !!u.is_admin, createdAt: u.created_at,
      })));
    } catch (error) {
      console.error('Admin users error:', error);
      return c.json({ error: 'Failed to fetch users' }, 500);
    }
  });

  app.post('/api/admin/users', authenticateToken, async (c: any) => {
    try {
      const { username, password, email, displayName, playerName } = await c.req.json();
      if (!username || !password || !email) {
        return c.json({ error: 'Username, password, and email required' }, 400);
      }

      const existing = await c.env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
      if (existing) return c.json({ error: 'Username already taken' }, 409);

      const emailExists = await c.env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
      if (emailExists) return c.json({ error: 'Email already registered' }, 409);

      const id = `user-${crypto.randomUUID()}`;
      const now = new Date().toISOString();
      const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

      await c.env.DB.prepare(`
        INSERT INTO users (id, username, password, email, display_name, player_name, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(id, username, hashedPassword, email, displayName || null, playerName || null, now, now).run();

      return c.json({ success: true, user: { id, username, email } }, 201);
    } catch (error) {
      console.error('Admin create user error:', error);
      return c.json({ error: 'Failed to create user' }, 500);
    }
  });

  app.put('/api/admin/users/:id', authenticateToken, async (c: any) => {
    try {
      const userId = c.req.param('id');
      const body = await c.req.json();
      const user = await c.env.DB.prepare('SELECT id, username FROM users WHERE id = ?').bind(userId).first();
      if (!user) return c.json({ error: 'User not found' }, 404);

      if (body.isAdmin !== undefined) {
        if (!body.isAdmin) {
          const adminCount = await c.env.DB.prepare('SELECT COUNT(*) as count FROM users WHERE is_admin = 1').first();
          if (adminCount && (adminCount as any).count <= 1) {
            return c.json({ error: 'Cannot remove the last admin' }, 400);
          }
        }
        await c.env.DB.prepare('UPDATE users SET is_admin = ? WHERE id = ?').bind(body.isAdmin ? 1 : 0, userId).run();
      }

      return c.json({ success: true, message: `User ${(user as any).username} updated` });
    } catch (error) {
      console.error('Update user error:', error);
      return c.json({ error: 'Failed to update user' }, 500);
    }
  });

  app.delete('/api/admin/users/:id', authenticateToken, async (c: any) => {
    try {
      const userId = c.req.param('id');
      const user = await c.env.DB.prepare('SELECT id, username, is_admin FROM users WHERE id = ?').bind(userId).first();
      if (!user) return c.json({ error: 'User not found' }, 404);

      if ((user as any).is_admin) {
        const adminCount = await c.env.DB.prepare('SELECT COUNT(*) as count FROM users WHERE is_admin = 1').first();
        if (adminCount && (adminCount as any).count <= 1) {
          return c.json({ error: 'Cannot delete the last admin' }, 400);
        }
      }

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

  // ── Admin: Claims ────────────────────────────────────

  app.get('/api/admin/claims', authenticateToken, async (c: any) => {
    try {
      const { status } = c.req.query();
      let query = `
        SELECT c.id, c.player_name, c.level_id, c.level_name, c.record_date, c.status, c.created_at,
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
        id: cl.id, player_name: cl.player_name, level_id: cl.level_id, level_name: cl.level_name,
        record_date: cl.record_date, status: cl.status, created_at: cl.created_at,
        username: cl.username, display_name: cl.displayName, userId: cl.userId,
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

      await c.env.DB.prepare('UPDATE claims SET status = ? WHERE id = ?').bind(status, (claim as any).id).run();

      if ((claim as any).player_name && status === 'approved') {
        await c.env.DB.prepare('UPDATE users SET player_name = ? WHERE id = ?').bind((claim as any).player_name, (claim as any).user_id).run();
      }

      const claimTarget = (claim as any).player_name || (claim as any).level_name;
      await createNotification(c.env.DB, (claim as any).user_id, 'claim_status',
        `Claim ${status}`,
        `Your claim on ${claimTarget} has been ${status}.`
      );

      return c.json({ success: true, message: `Claim ${status}` });
    } catch (error) {
      console.error('Update claim error:', error);
      return c.json({ error: 'Failed to update claim' }, 500);
    }
  });

  // ── IP Bans ──────────────────────────────────────────

  app.get('/api/ip-bans', authenticateToken, async (c: any) => {
    try {
      const bans = await c.env.DB.prepare(`SELECT ip, attempts, banned_until, updated_at FROM ip_bans ORDER BY updated_at DESC`).all();
      const now = Date.now();
      return c.json((bans.results || []).map((ban: any) => ({
        ip: ban.ip, attempts: ban.attempts, bannedUntil: ban.banned_until,
        isCurrentlyBanned: ban.banned_until > now,
        remainingTime: ban.banned_until > now ? Math.ceil((ban.banned_until - now) / 1000) : 0,
        updatedAt: ban.updated_at,
      })));
    } catch (error) {
      console.error('Error fetching IP bans:', error);
      return c.json({ error: 'Failed to fetch IP bans' }, 500);
    }
  });

  app.delete('/api/ip-bans/:ip', authenticateToken, async (c: any) => {
    try {
      await c.env.DB.prepare('DELETE FROM ip_bans WHERE ip = ?').bind(c.req.param('ip')).run();
      return c.json({ message: 'IP unbanned successfully', ip: c.req.param('ip') });
    } catch (error) {
      console.error('Error unbanning IP:', error);
      return c.json({ error: 'Failed to unban IP' }, 500);
    }
  });
}
