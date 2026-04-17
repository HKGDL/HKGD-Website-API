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
  SUGGESTIONS_PASSWORD: string;
};

const app = new Hono<{ Bindings: Bindings }>();

// Middleware
app.use('*', logger());
app.use('*', secureHeaders());

// CORS configuration
app.use('*', cors({
  origin: ['http://localhost:5173', 'https://hkgdl.dpdns.org', 'https://hkgd-website-frontend.hkgdl.workers.dev', 'geode://*', 'http://localhost:*', 'https://*.hkgdl.dpdns.org'],
  credentials: true,
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
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
    const adminPassword = c.env.ADMIN_PASSWORD;
    const suggestionsPassword = c.env.SUGGESTIONS_PASSWORD;
    const jwtSecret = c.env.JWT_SECRET;
    
    if (!adminPassword || !suggestionsPassword || !jwtSecret) {
      return c.json({ error: 'Server configuration error' }, 500);
    }
    
    // Check if IP is banned
    const { banned, remainingTime } = await isIPBanned(c.env.DB, ip);
    if (banned) {
      return c.json({
        error: 'IP banned',
        message: `Too many failed login attempts. Try again in ${Math.floor(remainingTime! / 60)} minutes.`,
        remainingTime
      }, 403);
    }
    
    // Check for full admin password
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
    }
    
    // Check for suggestions-only password
    if (password === suggestionsPassword) {
      await resetFailedAttempts(c.env.DB, ip);
      
      const secret = new TextEncoder().encode(jwtSecret);
      const token = await new SignJWT({ isAdmin: 'suggestions', timestamp: Date.now() })
        .setProtectedHeader({ alg: 'HS256' })
        .setExpirationTime('2h')
        .sign(secret);
      
      return c.json({
        success: true,
        user: { isAdmin: 'suggestions' },
        token
      });
    }
    
    // Invalid password
    const attempts = await recordFailedLogin(c.env.DB, ip);
    return c.json({
      success: false,
      error: 'Invalid password',
      attemptsRemaining: Math.max(0, MAX_LOGIN_ATTEMPTS - attempts),
      attempts
    }, 401);
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
        pack, gddl_tier as gddlTier, nlw_tier as nlwTier, edel_enjoyment as edelEnjoyment
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
        pack, gddl_tier as gddlTier, nlw_tier as nlwTier, edel_enjoyment as edelEnjoyment
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
      description, thumbnail, songId, songName, tags, dateAdded, pack, gddlTier, nlwTier, edelEnjoyment
    } = data;
    
    // Convert undefined to null for SQLite
    const safeBind = (val: any) => val ?? null;
    
    await c.env.DB.prepare(`
      INSERT INTO levels (
        id, hkgd_rank, aredl_rank, pemonlist_rank, name, creator, verifier, level_id,
        description, thumbnail, song_id, song_name, tags, date_added, pack, gddl_tier, nlw_tier, edel_enjoyment
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      safeBind(id), safeBind(hkgdRank), safeBind(aredlRank), safeBind(pemonlistRank),
      safeBind(name), safeBind(creator), safeBind(verifier), safeBind(levelId),
      safeBind(description), safeBind(thumbnail), safeBind(songId), safeBind(songName),
      JSON.stringify(tags || []), safeBind(dateAdded), safeBind(pack), safeBind(gddlTier), safeBind(nlwTier), safeBind(edelEnjoyment)
    ).run();
    
    return c.json({ id, message: 'Level created successfully' }, 201);
  } catch (error) {
    console.error('Error creating level:', error);
    return c.json({ error: 'Failed to create level', details: error instanceof Error ? error.message : 'Unknown error' }, 500);
  }
});

app.put('/api/levels/:id', authenticateToken, async (c) => {
  try {
    const data = await c.req.json();
    const {
      hkgdRank, aredlRank, pemonlistRank, name, creator, verifier, levelId,
      description, thumbnail, songId, songName, tags, dateAdded, pack, gddlTier, nlwTier
    } = data;
    
    // Convert undefined to null for SQLite
    const safeBind = (val: any) => val ?? null;
    
    await c.env.DB.prepare(`
      UPDATE levels SET
        hkgd_rank = ?, aredl_rank = ?, pemonlist_rank = ?, name = ?, creator = ?, verifier = ?,
        level_id = ?, description = ?, thumbnail = ?, song_id = ?, song_name = ?,
        tags = ?, date_added = ?, pack = ?, gddl_tier = ?, nlw_tier = ?
      WHERE id = ?
    `).bind(
      safeBind(hkgdRank), safeBind(aredlRank), safeBind(pemonlistRank),
      safeBind(name), safeBind(creator), safeBind(verifier), safeBind(levelId),
      safeBind(description), safeBind(thumbnail), safeBind(songId), safeBind(songName),
      JSON.stringify(tags || []), safeBind(dateAdded), safeBind(pack), safeBind(gddlTier), safeBind(nlwTier),
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
    const body = await c.req.json();
    const player = body.player;
    const date = body.date;
    const videoUrl = body.videoUrl || body.video_url;
    const fps = body.fps;
    const cbf = body.cbf;
    const attempts = body.attempts;
    
    // Convert undefined to null for SQLite
    const safeBind = (val: any) => val ?? null;
    
    const result = await c.env.DB.prepare(`
      INSERT INTO records (level_id, player, date, video_url, fps, cbf, attempts)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      c.req.param('levelId'),
      safeBind(player),
      safeBind(date),
      safeBind(videoUrl),
      safeBind(fps),
      cbf ? 1 : 0,
      safeBind(attempts)
    ).run();
    
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
    
    values.push(parseInt(recordId));
    const result = await c.env.DB.prepare(`UPDATE records SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
    
    if (result.meta.changes === 0) {
      return c.json({ error: 'Record not found' }, 404);
    }
    
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

// === PLAYER MAPPING ROUTES ===

app.get('/api/player-mapping', async (c) => {
  try {
    const { gameName } = c.req.query();
    
    if (!gameName) {
      return c.json({ error: 'gameName parameter required' }, 400);
    }
    
    const mapping = await c.env.DB.prepare(`
      SELECT db_name, account_id FROM player_mappings WHERE LOWER(game_name) = LOWER(?)
    `).bind(gameName.toString()).first();
    
    return c.json({
      dbName: mapping?.db_name || gameName,
      accountId: mapping?.account_id || null,
      isMapped: !!mapping
    });
  } catch (error) {
    console.error('Error fetching player mapping:', error);
    return c.json({ error: 'Failed to fetch player mapping' }, 500);
  }
});

app.post('/api/player-mapping', authenticateToken, async (c) => {
  try {
    const { gameName, dbName, accountId } = await c.req.json();
    
    if (!gameName || !dbName) {
      return c.json({ error: 'gameName and dbName are required' }, 400);
    }
    
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
    await c.env.DB.prepare('DELETE FROM player_mappings WHERE id = ?')
      .bind(c.req.param('id'))
      .run();
    
    return c.json({ success: true });
  } catch (error) {
    console.error('Error deleting player mapping:', error);
    return c.json({ error: 'Failed to delete player mapping' }, 500);
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
    
    // Convert undefined to null for optional fields (SQLite doesn't accept undefined)
    const safeOldRank = oldRank ?? null;
    const safeNewRank = newRank ?? null;
    
    await c.env.DB.prepare(`
      INSERT INTO changelog (id, date, level_name, level_id, change_type, old_rank, new_rank, description, list_type)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(id, date, levelName, levelId, change, safeOldRank, safeNewRank, description, listType || 'classic').run();
    
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
      id: s.id,
      levelId: s.level_id,
      levelName: s.level_name,
      isNewLevel: s.is_new_level === 1,
      record: JSON.parse(s.record_data),
      levelData: s.level_data ? JSON.parse(s.level_data) : null,
      submittedAt: s.submitted_at,
      submittedBy: s.submitted_by,
      status: s.status
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
    
    // Support both data formats
    const actualRecordData = record_data || JSON.stringify(record);
    const actualLevelData = level_data ? JSON.stringify(level_data) : null;
    
    await c.env.DB.prepare(`
      INSERT INTO pending_submissions (id, level_id, level_name, is_new_level, record_data, level_data, submitted_at, submitted_by, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      levelId,
      levelName,
      isNewLevel ? 1 : 0,
      actualRecordData,
      actualLevelData,
      submittedAt,
      submittedBy,
      status || 'pending'
    ).run();
    
    return c.json({ success: true, id, message: 'Submission created successfully' }, 201);
  } catch (error) {
    console.error('Error creating submission:', error);
    return c.json({ error: 'Failed to create submission' }, 500);
  }
});

app.put('/api/pending-submissions/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const { status } = await c.req.json();
    
    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return c.json({ error: 'Invalid status' }, 400);
    }
    
    await c.env.DB.prepare(`
      UPDATE pending_submissions SET status = ? WHERE id = ?
    `).bind(status, id).run();
    
    return c.json({ success: true, message: 'Submission updated successfully' });
  } catch (error) {
    console.error('Error updating submission:', error);
    return c.json({ error: 'Failed to update submission' }, 500);
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

// === SETTINGS ROUTES ===

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

// === IP BAN MANAGEMENT ===

app.get('/api/ip-bans', authenticateToken, async (c) => {
  try {
    const bans = await c.env.DB.prepare(`
      SELECT ip, attempts, banned_until, updated_at
      FROM ip_bans
      ORDER BY updated_at DESC
    `).all();
    
    const now = Date.now();
    const formattedBans = (bans.results || []).map((ban: any) => ({
      ip: ban.ip,
      attempts: ban.attempts,
      bannedUntil: ban.banned_until,
      isCurrentlyBanned: ban.banned_until > now,
      remainingTime: ban.banned_until > now ? Math.ceil((ban.banned_until - now) / 1000) : 0,
      updatedAt: ban.updated_at
    }));
    
    return c.json(formattedBans);
  } catch (error) {
    console.error('Error fetching IP bans:', error);
    return c.json({ error: 'Failed to fetch IP bans' }, 500);
  }
});

app.delete('/api/ip-bans/:ip', authenticateToken, async (c) => {
  try {
    const ip = c.req.param('ip');
    
    await c.env.DB.prepare('DELETE FROM ip_bans WHERE ip = ?').bind(ip).run();
    
    return c.json({ message: 'IP unbanned successfully', ip });
  } catch (error) {
    console.error('Error unbanning IP:', error);
    return c.json({ error: 'Failed to unban IP' }, 500);
  }
});

// === AREDL SYNC ===

app.post('/api/aredl-sync', authenticateToken, async (c) => {
  try {
    // Fetch AREDL levels from the official API
    const response = await fetch('https://api.aredl.net/v2/api/aredl/levels');
    if (!response.ok) {
      throw new Error('Failed to fetch AREDL data');
    }
    const aredlLevels = await response.json() as any[];
    
    // Get all current HKGD levels
    const currentLevels = await c.env.DB.prepare(`
      SELECT id, name, aredl_rank as aredlRank FROM levels
    `).all();
    
    const levelMap = new Map<string, { id: string; name: string; oldRank: number | null }>();
    for (const level of (currentLevels.results || [])) {
      levelMap.set((level as any).name.toLowerCase().trim(), {
        id: (level as any).id,
        name: (level as any).name,
        oldRank: (level as any).aredlRank
      });
    }
    
    // Create a map of level name -> AREDL data
    const aredlDataMap = new Map<string, any>();
    for (const aredlLevel of aredlLevels) {
      const name = aredlLevel.name?.toLowerCase().trim();
      if (name) {
        aredlDataMap.set(name, aredlLevel);
      }
    }
    
    // Update AREDL ranks and extra data for all matching levels
    const updates: { id: string; name: string; oldRank: number | null; newRank: number }[] = [];
    
    for (const [name, levelInfo] of levelMap) {
      const aredlData = aredlDataMap.get(name);
      if (aredlData) {
        const newRank = aredlData.position || aredlData.rank;
        const edelEnjoyment = aredlData.edel_enjoyment ?? null;
        const nlwTier = aredlData.nlw_tier ?? null;
        const gddlTier = aredlData.gddl_tier ?? null;
        
        await c.env.DB.prepare(`
          UPDATE levels SET aredl_rank = ?, edel_enjoyment = ?, nlw_tier = ?, gddl_tier = ? WHERE id = ?
        `).bind(newRank, edelEnjoyment, nlwTier, gddlTier, levelInfo.id).run();
        
        updates.push({
          id: levelInfo.id,
          name: levelInfo.name,
          oldRank: levelInfo.oldRank,
          newRank: newRank
        });
      }
    }
    
    // Re-sort HKGD ranks based on AREDL difficulty (lower AREDL rank = harder = lower HKGD rank)
    const sortedLevels = await c.env.DB.prepare(`
      SELECT id FROM levels 
      WHERE aredl_rank IS NOT NULL 
      ORDER BY aredl_rank ASC
    `).all();
    
    let hkgdRank = 1;
    for (const level of (sortedLevels.results || [])) {
      await c.env.DB.prepare(`
        UPDATE levels SET hkgd_rank = ? WHERE id = ?
      `).bind(hkgdRank, (level as any).id).run();
      hkgdRank++;
    }
    
    // Get levels without AREDL rank and assign them ranks after
    const unrankedLevels = await c.env.DB.prepare(`
      SELECT id FROM levels 
      WHERE aredl_rank IS NULL 
      ORDER BY hkgd_rank ASC
    `).all();
    
    for (const level of (unrankedLevels.results || [])) {
      await c.env.DB.prepare(`
        UPDATE levels SET hkgd_rank = ? WHERE id = ?
      `).bind(hkgdRank, (level as any).id).run();
      hkgdRank++;
    }
    
    // Create changelog entry for the sync
    const today = new Date();
    const dateStr = `${today.getFullYear().toString().slice(-2)}/${String(today.getMonth() + 1).padStart(2, '0')}/${String(today.getDate()).padStart(2, '0')}`;
    
    await c.env.DB.prepare(`
      INSERT INTO changelog (id, date, level_name, level_id, change_type, description, list_type)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      `sync-${Date.now()}`,
      dateStr,
      'AREDL Sync',
      'system',
      'sync',
      `AREDL sync completed. Updated ${updates.length} level rankings.`,
      'classic'
    ).run();
    
    return c.json({
      success: true,
      message: `Synced ${updates.length} levels with AREDL`,
      updatedLevels: updates.length,
      details: updates.slice(0, 10) // Return first 10 for preview
    });
  } catch (error) {
    console.error('AREDL sync error:', error);
    return c.json({ error: 'Failed to sync with AREDL', details: error instanceof Error ? error.message : 'Unknown error' }, 500);
  }
});

// === SUGGESTIONS ROUTES ===

// Get all suggestions (public)
app.get('/api/suggestions', async (c) => {
  try {
    const suggestions = await c.env.DB.prepare(`
      SELECT 
        id, type, title, description, level_id as levelId, level_name as levelName,
        submitted_by as submittedBy, submitted_at as submittedAt, status,
        admin_notes as adminNotes, resolved_at as resolvedAt, resolved_by as resolvedBy
      FROM suggestions
      ORDER BY submitted_at DESC
    `).all();
    
    return c.json(suggestions.results || []);
  } catch (error) {
    console.error('Error fetching suggestions:', error);
    return c.json({ error: 'Failed to fetch suggestions' }, 500);
  }
});

// Get pending suggestions (for admin panel)
app.get('/api/suggestions/pending', async (c) => {
  try {
    const suggestions = await c.env.DB.prepare(`
      SELECT 
        id, type, title, description, level_id as levelId, level_name as levelName,
        submitted_by as submittedBy, submitted_at as submittedAt, status,
        admin_notes as adminNotes, resolved_at as resolvedAt, resolved_by as resolvedBy
      FROM suggestions
      WHERE status = 'pending'
      ORDER BY submitted_at DESC
    `).all();
    
    return c.json(suggestions.results || []);
  } catch (error) {
    console.error('Error fetching pending suggestions:', error);
    return c.json({ error: 'Failed to fetch pending suggestions' }, 500);
  }
});

// Create a new suggestion (public)
app.post('/api/suggestions', async (c) => {
  try {
    const data = await c.req.json();
    const { type, title, description, levelId, levelName, submittedBy } = data;
    
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

// Update suggestion status (admin only)
app.put('/api/suggestions/:id', authenticateToken, async (c) => {
  try {
    const id = c.req.param('id');
    const { status, adminNotes } = await c.req.json();
    
    if (!['pending', 'approved', 'rejected', 'fixed', 'in_progress'].includes(status)) {
      return c.json({ error: 'Invalid status' }, 400);
    }
    
    const resolvedAt = status !== 'pending' ? new Date().toISOString() : null;
    const user = c.get('user') as any;
    const resolvedBy = status !== 'pending' ? (user.isAdmin === true ? 'admin' : 'suggestions_admin') : null;
    
    await c.env.DB.prepare(`
      UPDATE suggestions SET status = ?, admin_notes = ?, resolved_at = ?, resolved_by = ? WHERE id = ?
    `).bind(status, adminNotes || null, resolvedAt, resolvedBy, id).run();
    
    return c.json({ success: true, message: 'Suggestion updated successfully' });
  } catch (error) {
    console.error('Error updating suggestion:', error);
    return c.json({ error: 'Failed to update suggestion' }, 500);
  }
});

// Delete suggestion (admin only)
app.delete('/api/suggestions/:id', authenticateToken, async (c) => {
  try {
    const id = c.req.param('id');
    
    await c.env.DB.prepare('DELETE FROM suggestions WHERE id = ?').bind(id).run();
    
    return c.json({ success: true, message: 'Suggestion deleted successfully' });
  } catch (error) {
    console.error('Error deleting suggestion:', error);
    return c.json({ error: 'Failed to delete suggestion' }, 500);
  }
});

// Health check
app.get('/api/health', (c) => c.json({ status: 'ok', timestamp: new Date().toISOString() }));

export default app;
