import { Hono } from 'hono';
import { Bindings, safe } from '../types';
import { authenticateToken } from '../helpers/auth';
import { computePoints } from '../helpers/utils';
import { notifyContentChanged } from '../helpers/indexnow';

export function registerPlatformerRoutes(app: Hono<{ Bindings: Bindings }>) {
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

  app.get('/api/platformer-demons', async (c) => {
    try {
      const levels = await c.env.DB.prepare(`
        SELECT id, hkgd_rank as hkgdRank, name, creator, verifier, level_id as levelId, description, thumbnail,
          song_id as songId, song_name as songName, tags, date_added as dateAdded, pack, difficulty
        FROM platformer_levels ORDER BY hkgd_rank ASC
      `).all();
      return c.json({ demons: levels.results || [] });
    } catch (error) {
      console.error('Error fetching platformer demons:', error);
      return c.json({ error: 'Failed to fetch platformer demons' }, 500);
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
      const record = await c.env.DB.prepare('SELECT level_id FROM platformer_records WHERE id = ?').bind(recordId).first() as any;
      if (!record) return c.json({ error: 'Platformer record not found' }, 404);
      await c.env.DB.prepare('DELETE FROM platformer_records WHERE id = ?').bind(recordId).run();
      const remaining = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM platformer_records WHERE level_id = ?').bind(record.level_id).first() as any;
      if (remaining && remaining.cnt === 0) {
        await c.env.DB.prepare('DELETE FROM platformer_levels WHERE id = ?').bind(record.level_id).run();
      }
      return c.json({ message: 'Platformer record deleted successfully' });
    } catch (error) {
      console.error('Error deleting platformer record:', error);
      return c.json({ error: 'Failed to delete platformer record' }, 500);
    }
  });

  // ── Platformer Sync Details ──────────────────────────

  app.post('/api/platformer-levels/sync-details', authenticateToken, async (c: any) => {
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

  app.post('/api/platformer-levels/bulk-import', authenticateToken, async (c: any) => {
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

  // ── Platformer Level Sync ────────────────────────────

  app.post('/api/platformer-levels/sync', authenticateToken, async (c: any) => {
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
}
