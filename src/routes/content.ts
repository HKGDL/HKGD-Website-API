import { Hono } from 'hono';
import { Bindings, safe } from '../types';
import { authenticateToken } from '../helpers/auth';

export function registerContentRoutes(app: Hono<{ Bindings: Bindings }>) {
  // ── Changelog ────────────────────────────────────────

  app.get('/api/changelog', async (c) => {
    try {
      const changelog = await c.env.DB.prepare(`
        SELECT id, date, level_name as levelName, level_id as levelId,
          change_type as change, old_rank as oldRank, new_rank as newRank,
          description, list_type as listType
        FROM changelog ORDER BY date DESC
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

  // ── Members ──────────────────────────────────────────

  app.get('/api/members', async (c) => {
    try {
      const members = await c.env.DB.prepare(`
        SELECT id, name, country, levels_beaten as levelsBeaten, avatar
        FROM members ORDER BY levels_beaten DESC
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
        FROM player_mappings ORDER BY created_at DESC
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

  // ── MOTD ─────────────────────────────────────────────

  app.get('/api/motd', async (c) => {
    try {
      const rows = await c.env.DB.prepare('SELECT id, message FROM motd ORDER BY id').all();
      const messages: Record<string, string> = {};
      const types: string[] = [];
      for (const row of (rows.results || [])) {
        const r = row as any;
        types.push(r.id);
        messages[r.id] = r.message || '';
      }
      if (types.length === 0) {
        types.push('main');
        messages['main'] = '';
      }
      return c.json({ types, messages });
    } catch { return c.json({ types: ['main'], messages: { main: '' } }); }
  });

  app.put('/api/motd', authenticateToken, async (c: any) => {
    try {
      const { type, message } = await c.req.json();
      const motdType = type || 'main';
      const updatedAt = new Date().toISOString();
      const user = c.get('user') as any;
      await c.env.DB.prepare(`
        INSERT INTO motd (id, message, updated_at, updated_by)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET message = excluded.message, updated_at = excluded.updated_at, updated_by = excluded.updated_by
      `).bind(motdType, message, updatedAt, user?.isAdmin === true ? 'admin' : 'suggestions').run();
      return c.json({ type: motdType, message, updatedAt });
    } catch (error) {
      console.error('Error updating MOTD:', error);
      return c.json({ error: 'Failed to update MOTD' }, 500);
    }
  });

  app.post('/api/motd/sync-from-discord', authenticateToken, async (c: any) => {
    try {
      const { syncMotdFromDiscord, saveMotdTypes } = await import('../helpers/cron');
      const result = await syncMotdFromDiscord(c.env);
      const typeKeys = Object.keys(result.types);
      if (typeKeys.length === 0) return c.json({ error: 'No MOTD messages found in Discord' }, 500);
      const updatedAt = new Date().toISOString();
      const syncedTypes: Record<string, string> = {};
      await saveMotdTypes(c.env, result.types, updatedAt);
      for (const type of typeKeys) {
        syncedTypes[type] = result.types[type].levelId;
      }
      return c.json({ success: true, types: syncedTypes });
    } catch (error) {
      console.error('Error syncing MOTD from Discord:', error);
      return c.json({ error: 'Failed to sync MOTD from Discord' }, 500);
    }
  });
}
