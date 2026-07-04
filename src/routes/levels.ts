import { Hono } from 'hono';
import { Bindings, safe } from '../types';
import { authenticateToken } from '../helpers/auth';
import { computePoints } from '../helpers/utils';
import { notifyContentChanged } from '../helpers/indexnow';

export function registerLevelRoutes(app: Hono<{ Bindings: Bindings }>) {
  app.get('/api/levels', async (c) => {
    try {
      const levels = await c.env.DB.prepare(`
        SELECT
          id, hkgd_rank as hkgdRank, aredl_rank as aredlRank, pemonlist_rank as pemonlistRank,
          name, creator, verifier, level_id as levelId, description, thumbnail,
          song_id as songId, song_name as songName, tags, date_added as dateAdded,
          pack, gddl_tier as gddlTier, nlw_tier as nlwTier, edel_enjoyment as edelEnjoyment
        FROM levels
        WHERE hidden IS NULL OR hidden != 1
        ORDER BY hkgd_rank ASC
      `).all();

      const allRecords = await c.env.DB.prepare(`
        SELECT id, level_id, player, date, video_url as videoUrl, fps, cbf, attempts, points
        FROM records ORDER BY date DESC
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
        FROM levels WHERE id = ?
      `).bind(c.req.param('id')).first();

      if (!level) return c.json({ error: 'Level not found' }, 404);

      const records = await c.env.DB.prepare(`
        SELECT id, player, date, video_url as videoUrl, fps, cbf, attempts, points
        FROM records WHERE level_id = ? ORDER BY date DESC
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
      const record = await c.env.DB.prepare('SELECT level_id FROM records WHERE id = ?').bind(recordId).first() as any;
      if (!record) return c.json({ error: 'Record not found' }, 404);
      await c.env.DB.prepare('DELETE FROM records WHERE id = ?').bind(recordId).run();
      const remaining = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM records WHERE level_id = ?').bind(record.level_id).first() as any;
      if (remaining && remaining.cnt === 0) {
        await c.env.DB.prepare('DELETE FROM levels WHERE id = ?').bind(record.level_id).run();
      }
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
        await c.env.DB.prepare('UPDATE records SET points = ? WHERE level_id = ? AND points IS NULL')
          .bind(points, (level as any).id).run();
        updated++;
      }

      return c.json({ success: true, message: `Set points for ${updated} levels (existing points preserved)` });
    } catch (error) {
      console.error('Recalculate points error:', error);
      return c.json({ error: 'Failed to recalculate points' }, 500);
    }
  });
}
