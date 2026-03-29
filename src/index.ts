import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { secureHeaders } from 'hono/secure-headers';
import { SignJWT, jwtVerify } from 'jose';
import { validator } from 'hono/validator';

type Bindings = {
  DB: D1Database;
  ENVIRONMENT: string;
  JWT_SECRET: string;
  ADMIN_PASSWORD: string;
};

const app = new Hono<{ Bindings: Bindings }>();

// Middleware
app.use('*', logger());
app.use('*', secureHeaders());

// CORS configuration
app.use('*', cors({
  origin: ['http://localhost:5173', 'https://hkgdl.dpdns.org'],
  credentials: true,
}));

// Helper functions
function getClientIP(c: any): string {
  let ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ||
           c.req.header('x-real-ip')?.trim() ||
           '127.0.0.1';
  
  if (ip === '::1' || ip === '::ffff:127.0.0.1') {
    ip = '127.0.0.1';
  }
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }
  return ip || '127.0.0.1';
}

// IP Ban Management (using D1 for persistence)
const MAX_LOGIN_ATTEMPTS = 5;
const BAN_DURATION = 15 * 60 * 1000; // 15 minutes

async function isIPBanned(db: D1Database, ip: string): Promise<{ banned: boolean; remainingTime?: number }> {
  const result = await db.prepare(
    'SELECT banned_until FROM ip_bans WHERE ip = ? AND banned_until > ?'
  ).bind(ip, Date.now()).first();
  
  if (result) {
    const remainingTime = Math.ceil((result.banned_until as number - Date.now()) / 1000);
    return { banned: true, remainingTime };
  }
  return { banned: false };
}

async function recordFailedLogin(db: D1Database, ip: string): Promise<number> {
  // Get current attempts
  const existing = await db.prepare(
    'SELECT attempts FROM ip_bans WHERE ip = ?'
  ).bind(ip).first();
  
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

// JWT Authentication Middleware
async function authenticateToken(c: any, next: any) {
  const token = c.req.header('Authorization')?.replace('Bearer ', '') || 
                c.req.header('Cookie')?.match(/hkgd_admin_token=([^;]+)/)?.[1];
  
  if (!token) {
    return c.json({ error: 'Access token required' }, 401);
  }
  
  try {
    const secret = new TextEncoder().encode(c.env.JWT_SECRET || 'hkgd-secret-key-2024');
    const { payload } = await jwtVerify(token, secret);
    c.set('user', payload);
    await next();
  } catch (err) {
    return c.json({ error: 'Invalid or expired token' }, 403);
  }
}

// === AUTH ROUTES ===

app.post('/api/auth/login', async (c) => {
  try {
    const { password } = await c.req.json();
    const ip = getClientIP(c);
    const adminPassword = c.env.ADMIN_PASSWORD || 'hkgdadmin2024';
    const jwtSecret = c.env.JWT_SECRET || 'hkgd-secret-key-2024';
    
    // Check if IP is banned
    const { banned, remainingTime } = await isIPBanned(c.env.DB, ip);
    if (banned) {
      return c.json({
        error: 'IP banned',
        message: `Too many failed login attempts. Try again in ${Math.floor(remainingTime! / 60)} minutes.`,
        remainingTime
      }, 403);
    }
    
    if (password === adminPassword) {
      await resetFailedAttempts(c.env.DB, ip);
      
      const secret = new TextEncoder().encode(jwtSecret);
      const token = await new SignJWT({ isAdmin: true, timestamp: Date.now() })
        .setProtectedHeader({ alg: 'HS256' })
        .setExpirationTime('2h')
        .sign(secret);
      
      return c.json({
        success: true,
        user: { isAdmin: true },
        token
      });
    } else {
      const attempts = await recordFailedLogin(c.env.DB, ip);
      return c.json({
        success: false,
        error: 'Invalid password',
        attemptsRemaining: Math.max(0, MAX_LOGIN_ATTEMPTS - attempts),
        attempts
      }, 401);
    }
  } catch (error) {
    console.error('Login error:', error);
    return c.json({ error: 'Login failed' }, 500);
  }
});

app.post('/api/auth/verify', authenticateToken, async (c) => {
  return c.json({ success: true, user: c.get('user') });
});

app.post('/api/auth/logout', async (c) => {
  return c.json({ success: true, message: 'Logged out successfully' });
});

// === LEVELS ROUTES ===

app.get('/api/levels', async (c) => {
  try {
    // Single query for all levels
    const levels = await c.env.DB.prepare(`
      SELECT
        id, hkgd_rank as hkgdRank, aredl_rank as aredlRank, pemonlist_rank as pemonlistRank,
        name, creator, verifier, level_id as levelId, description, thumbnail,
        song_id as songId, song_name as songName, tags, date_added as dateAdded,
        pack, gddl_tier as gddlTier, nlw_tier as nlwTier
      FROM levels
      ORDER BY hkgd_rank ASC
    `).all();
    
    // Single query for ALL records (instead of N+1 queries)
    const allRecords = await c.env.DB.prepare(`
      SELECT id, level_id, player, date, video_url as videoUrl, fps, cbf, attempts
      FROM records
      ORDER BY date DESC
    `).all();
    
    // Group records by level_id in memory
    const recordsByLevel: Record<string, any[]> = {};
    for (const r of (allRecords.results || [])) {
      if (!recordsByLevel[r.level_id as string]) {
        recordsByLevel[r.level_id as string] = [];
      }
      recordsByLevel[r.level_id as string].push({ ...r, cbf: r.cbf === 1 });
    }
    
    // Combine levels with their records
    const levelsWithRecords = (levels.results || []).map((level: any) => ({
      ...level,
      songName: level.songName && level.songName !== 'undefined by undefined' ? level.songName : null,
      tags: level.tags ? JSON.parse(level.tags) : [],
      records: recordsByLevel[level.id] || []
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
        pack, gddl_tier as gddlTier, nlw_tier as nlwTier
      FROM levels
      WHERE id = ?
    `).bind(c.req.param('id')).first();
    
    if (!level) {
      return c.json({ error: 'Level not found' }, 404);
    }
    
    const records = await c.env.DB.prepare(`
      SELECT id, player, date, video_url as videoUrl, fps, cbf, attempts
      FROM records
      WHERE level_id = ?
      ORDER BY date DESC
    `).bind(c.req.param('id')).all();
    
    return c.json({
      ...level,
      tags: (level.tags as string) ? JSON.parse(level.tags as string) : [],
      records: (records.results || []).map((r: any) => ({ ...r, cbf: r.cbf === 1 }))
    });
  } catch (error) {
    console.error('Error fetching level:', error);
    return c.json({ error: 'Failed to fetch level' }, 500);
  }
});

app.post('/api/levels', authenticateToken, async (c) => {
  try {
    const data = await c.req.json();
    const {
      id, hkgdRank, aredlRank, pemonlistRank, name, creator, verifier, levelId,
      description, thumbnail, songId, songName, tags, dateAdded, pack, gddlTier, nlwTier
    } = data;
    
    await c.env.DB.prepare(`
      INSERT INTO levels (
        id, hkgd_rank, aredl_rank, pemonlist_rank, name, creator, verifier, level_id,
        description, thumbnail, song_id, song_name, tags, date_added, pack, gddl_tier, nlw_tier
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id, hkgdRank, aredlRank, pemonlistRank, name, creator, verifier, levelId,
      description, thumbnail, songId, songName, JSON.stringify(tags), dateAdded, pack, gddlTier, nlwTier
    ).run();
    
    return c.json({ id, message: 'Level created successfully' }, 201);
  } catch (error) {
    console.error('Error creating level:', error);
    return c.json({ error: 'Failed to create level' }, 500);
  }
});

app.put('/api/levels/:id', authenticateToken, async (c) => {
  try {
    const data = await c.req.json();
    const {
      hkgdRank, aredlRank, pemonlistRank, name, creator, verifier, levelId,
      description, thumbnail, songId, songName, tags, dateAdded, pack, gddlTier, nlwTier
    } = data;
    
    await c.env.DB.prepare(`
      UPDATE levels SET
        hkgd_rank = ?, aredl_rank = ?, pemonlist_rank = ?, name = ?, creator = ?, verifier = ?,
        level_id = ?, description = ?, thumbnail = ?, song_id = ?, song_name = ?,
        tags = ?, date_added = ?, pack = ?, gddl_tier = ?, nlw_tier = ?
      WHERE id = ?
    `).bind(
      hkgdRank, aredlRank, pemonlistRank, name, creator, verifier, levelId,
      description, thumbnail, songId, songName, JSON.stringify(tags), dateAdded, pack, gddlTier, nlwTier,
      c.req.param('id')
    ).run();
    
    return c.json({ message: 'Level updated successfully' });
  } catch (error) {
    console.error('Error updating level:', error);
    return c.json({ error: 'Failed to update level' }, 500);
  }
});

app.delete('/api/levels/:id', authenticateToken, async (c) => {
  try {
    await c.env.DB.prepare('DELETE FROM levels WHERE id = ?').bind(c.req.param('id')).run();
    return c.json({ message: 'Level deleted successfully' });
  } catch (error) {
    console.error('Error deleting level:', error);
    return c.json({ error: 'Failed to delete level' }, 500);
  }
});

// === RECORDS ROUTES ===

app.post('/api/levels/:levelId/records', authenticateToken, async (c) => {
  try {
    const { player, date, videoUrl, fps, cbf, attempts } = await c.req.json();
    
    if (!videoUrl || videoUrl.length < 10) {
      return c.json({ error: 'Valid video URL is required' }, 400);
    }
    
    const result = await c.env.DB.prepare(`
      INSERT INTO records (level_id, player, date, video_url, fps, cbf, attempts)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(c.req.param('levelId'), player, date, videoUrl, fps, cbf ? 1 : 0, attempts).run();
    
    return c.json({ message: 'Record added successfully', id: result.meta.last_row_id }, 201);
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
    
    const fields = ['player', 'date', 'video_url', 'fps', 'cbf', 'attempts'];
    const dataMap: any = {
      player: data.player,
      date: data.date,
      video_url: data.videoUrl,
      fps: data.fps,
      cbf: data.cbf ? 1 : 0,
      attempts: data.attempts
    };
    
    for (const field of fields) {
      if (dataMap[field] !== undefined) {
        updates.push(`${field} = ?`);
        values.push(dataMap[field]);
      }
    }
    
    if (updates.length === 0) {
      return c.json({ error: 'No fields to update' }, 400);
    }
    
    values.push(recordId);
    await c.env.DB.prepare(`UPDATE records SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
    
    return c.json({ message: 'Record updated successfully' });
  } catch (error) {
    console.error('Error updating record:', error);
    return c.json({ error: 'Failed to update record' }, 500);
  }
});

app.delete('/api/records/:recordId', authenticateToken, async (c) => {
  try {
    const result = await c.env.DB.prepare('DELETE FROM records WHERE id = ?').bind(c.req.param('recordId')).run();
    
    if (result.meta.changes === 0) {
      return c.json({ error: 'Record not found' }, 404);
    }
    
    return c.json({ message: 'Record deleted successfully' });
  } catch (error) {
    console.error('Error deleting record:', error);
    return c.json({ error: 'Failed to delete record' }, 500);
  }
});

// === MEMBERS ROUTES ===

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

// === CHANGELOG ROUTES ===

app.get('/api/changelog', async (c) => {
  try {
    const changelog = await c.env.DB.prepare(`
      SELECT
        id, date, level_name as levelName, level_id as levelId,
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
    `).bind(id, date, levelName, levelId, change, oldRank, newRank, description, listType || 'classic').run();
    
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

// === CONTENT ROUTES ===

app.get('/api/content', async (c) => {
  try {
    const contentRow = await c.env.DB.prepare("SELECT content_json FROM website_content WHERE id = 'main'").first();
    
    if (contentRow) {
      return c.json(JSON.parse(contentRow.content_json as string));
    }
    
    // Return default content
    return c.json({
      hero: { title: "HKGD DEMON LIST", subtitle: "Hong Kong Geometry Dash Community" },
      stats: { levelsLabel: "Levels Listed", playersLabel: "Players", hardestLabel: "Hardest AREDL" },
      listPage: { title: "Demon List", description: "All Extreme Demon levels beaten by HKGD members." },
      platformerPage: { title: "Platformer Demon List" },
      submitPage: { title: "Submit Record" },
      footer: { description: "The official demon list for the Hong Kong Geometry Dash community." }
    });
  } catch (error) {
    console.error('Error fetching content:', error);
    return c.json({ error: 'Failed to fetch content' }, 500);
  }
});

app.post('/api/content', authenticateToken, async (c) => {
  try {
    const content = await c.req.json();
    const content_json = JSON.stringify(content);
    const updated_at = new Date().toISOString();
    
    await c.env.DB.prepare(`
      INSERT INTO website_content (id, content_json, updated_at)
      VALUES ('main', ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        content_json = excluded.content_json,
        updated_at = excluded.updated_at
    `).bind(content_json, updated_at).run();
    
    return c.json({ message: 'Content saved successfully' });
  } catch (error) {
    console.error('Error saving content:', error);
    return c.json({ error: 'Failed to save content' }, 500);
  }
});

// === PENDING SUBMISSIONS ===

app.get('/api/pending-submissions', async (c) => {
  try {
    const submissions = await c.env.DB.prepare(`
      SELECT * FROM pending_submissions WHERE status = 'pending' ORDER BY submitted_at DESC
    `).all();
    
    return c.json((submissions.results || []).map((s: any) => ({
      ...s,
      record_data: JSON.parse(s.record_data),
      level_data: s.level_data ? JSON.parse(s.level_data) : null
    })));
  } catch (error) {
    console.error('Error fetching submissions:', error);
    return c.json({ error: 'Failed to fetch submissions' }, 500);
  }
});

// === PLATFORMER DEMONS PROXY ===

app.get('/api/platformer-demons', async (c) => {
  try {
    const response = await fetch('https://pemonlist.com/api/platformer-demons?limit=500');
    const data = await response.json() as any;
    return c.json(data);
  } catch (error) {
    console.error('Error fetching platformer demons:', error);
    return c.json({ error: 'Failed to fetch platformer demons' }, 500);
  }
});

// Health check
app.get('/api/health', (c) => c.json({ status: 'ok', timestamp: new Date().toISOString() }));

export default app;
