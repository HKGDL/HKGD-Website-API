import { Hono } from 'hono';
import { Bindings } from '../types';
import { authenticateToken } from '../helpers/auth';
import { syncAredlRankings } from '../helpers/cron';
import { notifyContentChanged } from '../helpers/indexnow';

const GD_TRACKS = [
  'Stereo Madness','Back on Track','Polargeist','Dry Out','Base After Base',
  "Can't Let Go",'Jumper','Time Machine','Cycles','xStep',
  'Clutterfunk','Electroman Adventures','Clubstep','Electrodynamix','Hexagon Force',
  'Blast Processing','Theory of Everything','Theory of Everything 2','Geometric Dominator','Deadlocked',
  'Fingerdash','Dash'
];

export function registerSyncRoutes(app: Hono<{ Bindings: Bindings }>) {
  // ── AREDL Sync ───────────────────────────────────────

  app.post('/api/aredl-sync', authenticateToken, async (c: any) => {
    try {
      const body = await c.req.json().catch(() => ({}));
      let aredlLevels: any[] = body.aredlLevels;

      if (!aredlLevels || !aredlLevels.length) {
        return c.json({ error: 'No AREDL data provided. The browser must fetch AREDL data and send it here.' }, 400);
      }

      const currentLevels = await c.env.DB.prepare('SELECT id, name, aredl_rank as aredlRank FROM levels').all();
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

      let updatedCount = 0;
      for (const [name, levelInfo] of levelMap) {
        const aredlData = aredlDataMap.get(name);
        if (aredlData) {
          await c.env.DB.prepare(`
            UPDATE levels SET aredl_rank = ?, edel_enjoyment = ?, nlw_tier = ?, gddl_tier = ? WHERE id = ?
          `).bind(aredlData.position || aredlData.rank, aredlData.edel_enjoyment ?? null, aredlData.nlw_tier ?? null, aredlData.gddl_tier ?? null, levelInfo.id).run();
          updatedCount++;
        }
      }

      const sortedLevels = await c.env.DB.prepare(
        'SELECT id FROM levels WHERE aredl_rank IS NOT NULL AND (hidden IS NULL OR hidden != 1) ORDER BY aredl_rank ASC'
      ).all();
      let hkgdRank = 1;
      for (const level of (sortedLevels.results || [])) {
        await c.env.DB.prepare('UPDATE levels SET hkgd_rank = ? WHERE id = ?').bind(hkgdRank, (level as any).id).run();
        hkgdRank++;
      }

      const unrankedLevels = await c.env.DB.prepare(
        'SELECT id FROM levels WHERE aredl_rank IS NULL AND (hidden IS NULL OR hidden != 1) ORDER BY hkgd_rank ASC'
      ).all();
      for (const level of (unrankedLevels.results || [])) {
        await c.env.DB.prepare('UPDATE levels SET hkgd_rank = ? WHERE id = ?').bind(hkgdRank, (level as any).id).run();
        hkgdRank++;
      }

      await c.env.DB.prepare('UPDATE levels SET hkgd_rank = 0 WHERE hidden = 1').run();

      const today = new Date();
      const dateStr = `${today.getFullYear().toString().slice(-2)}/${String(today.getMonth() + 1).padStart(2, '0')}/${String(today.getDate()).padStart(2, '0')}`;
      await c.env.DB.prepare(`
        INSERT INTO changelog (id, date, level_name, level_id, change_type, description, list_type)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).bind(`sync-${Date.now()}`, dateStr, 'AREDL Sync', 'system', 'sync', `AREDL sync completed. Updated ${updatedCount} level rankings.`, 'classic').run();

      notifyContentChanged(c.env);
      return c.json({ success: true, message: `Synced ${updatedCount} levels with AREDL`, updatedLevels: updatedCount });
    } catch (error) {
      console.error('AREDL sync error:', error);
      return c.json({ error: 'Failed to sync with AREDL', details: error instanceof Error ? error.message : 'Unknown error' }, 500);
    }
  });

  // ── Google Sheets Sync ───────────────────────────────

  app.post('/api/google-sheets/sync', authenticateToken, async (c: any) => {
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
      const existingRecordSet = new Set((allRecords.results || []).map((r: any) => `${r.level_id}|${(r.player || '').toLowerCase()}|${r.date}`));

      const now = new Date().toISOString();
      let addedLevels = 0, addedRecords = 0;
      const levelsToInsert: any[] = [];
      const recordsToInsert: any[] = [];

      const rankUpdates: { gameId: string; hkgdRank: number; aredlRank: number | null }[] = [];

      for (const row of rows.slice(1)) {
        if (row.length < 5) continue;
        const placement = row[0]?.toString().trim();
        const gameId = row[2]?.toString().trim();
        const levelName = row[3]?.toString().trim();
        if (!gameId || !levelName) continue;
        const victorsRaw = row[4]?.toString().trim();
        if (!victorsRaw || !/^\d+$/.test(victorsRaw) || parseInt(victorsRaw, 10) < 1) continue;

        const aredlRank = placement && !isNaN(Number(placement)) ? parseInt(placement) : null;
        const existing = levelByGameId.get(gameId);
        const dbId = existing ? (existing as any).id : gameId;

        if (existing) {
          if (aredlRank !== null) {
            rankUpdates.push({ gameId, hkgdRank: aredlRank, aredlRank });
          }
        } else if (!existingNames.has(levelName.toLowerCase())) {
          levelsToInsert.push({ id: gameId, gameId, name: levelName, aredlRank, hkgdRank: aredlRank });
          addedLevels++;
        }

        for (let pi = 0; pi < 50; pi++) {
          const base = 5 + pi * 4;
          if (base >= row.length) break;
          const date = row[base]?.toString().trim();
          const player = row[base + 1]?.toString().trim();
          if (!date || !player) continue;
          const normalizedDate = /^\d{2}[\/\-]\d{2}[\/\-]\d{2}$/.test(date) ? `20${date}` : date;
          if (!/^\d{4}[\/\-]\d{2}[\/\-]\d{2}$/.test(normalizedDate)) continue;
          const video = (base + 2 < row.length) ? row[base + 2]?.toString().trim() : '';
          const fpsRaw = (base + 3 < row.length) ? row[base + 3]?.toString().trim() : '';
          if (!existingRecordSet.has(`${dbId}|${player.toLowerCase()}|${normalizedDate}`)) {
            const fps = fpsRaw && fpsRaw !== '/' ? parseInt(fpsRaw.replace(/[^0-9]/g, '')) || null : null;
            const videoUrl = video && video !== '/' && video.length > 0 ? video : null;
            recordsToInsert.push({ levelId: dbId, player, date: normalizedDate, videoUrl, fps });
            existingRecordSet.add(`${dbId}|${player.toLowerCase()}|${normalizedDate}`);
            addedRecords++;
          }
        }
      }

      const insertStmts = levelsToInsert.map(l => c.env.DB.prepare(`
        INSERT OR IGNORE INTO levels (id, hkgd_rank, aredl_rank, name, creator, verifier, level_id, tags, date_added)
        VALUES (?, ?, ?, ?, '', '', ?, ?, ?)
      `).bind(l.id, l.hkgdRank || 0, l.aredlRank, l.name, l.gameId, JSON.stringify(l.aredlRank ? ['Overall'] : []), now));
      if (insertStmts.length) await c.env.DB.batch(insertStmts);

      let updatedRanks = 0;
      if (rankUpdates.length) {
        const rankStmts = rankUpdates.map(r => c.env.DB.prepare(`
          UPDATE levels SET hkgd_rank = ?, aredl_rank = ? WHERE level_id = ?
        `).bind(r.hkgdRank, r.aredlRank, r.gameId));
        for (let i = 0; i < rankStmts.length; i += 80) {
          try { await c.env.DB.batch(rankStmts.slice(i, i + 80)); updatedRanks += Math.min(80, rankStmts.length - i); } catch {}
        }
      }

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
        `Added ${addedLevels} levels · Added ${addedRecords} records · Updated ${updatedRanks} ranks`, 'classic').run();

      return c.json({ success: true, message: `Synced: ${addedLevels} levels, ${addedRecords} records, ${updatedRanks} ranks updated`, addedLevels, addedRecords, updatedRanks });
    } catch (error) {
      console.error('Google Sheets sync error:', error);
      return c.json({ error: 'Sync failed', details: error instanceof Error ? error.message : String(error) }, 500);
    }
  });

  // ── Sync Level Details ───────────────────────────────

  app.post('/api/levels/sync-details', authenticateToken, async (c: any) => {
    try {
      await c.env.DB.prepare(`
        UPDATE levels SET thumbnail = 'https://levelthumbs.prevter.me/thumbnail/' || level_id
        WHERE level_id IS NOT NULL AND level_id != ''
      `).run();

      let aredlMap: Record<string, any> = {};
      try {
        const aredlRes = await fetch('https://api.aredl.net/v2/api/aredl/levels?page=1&limit=2000');
        if (aredlRes.ok) {
          const aredlData = await aredlRes.json() as any[];
          for (const l of aredlData) {
            if (l.level_id) aredlMap[String(l.level_id)] = { song: l.song, description: l.description };
          }
        }
      } catch (e) { console.error('AREDL fetch failed:', e); }

      const levels = await c.env.DB.prepare(`
        SELECT id, level_id, name, creator, verifier, thumbnail, song_id, song_name
        FROM levels ORDER BY hkgd_rank ASC
      `).all();

      const levelList = levels.results || [];
      const updates: any[] = [];

      for (const level of levelList) {
        const updatesObj: any = {};

        let historyGdHit: any = null;
        try {
          const response = await fetch(
            `https://history.geometrydash.eu/api/v1/search/level/advanced/?query=${level.level_id}&limit=1&filter=online_id%3D${level.level_id}`
          );
          if (response.ok) {
            const data = await response.json() as any;
            historyGdHit = data.hits?.[0];
            if (historyGdHit) {
              let historySongId: string | null = null;
              if (historyGdHit.cache_song_id > 0) {
                historySongId = String(historyGdHit.cache_song_id);
              } else if (historyGdHit.cache_audiotrack > 0) {
                historySongId = String(-historyGdHit.cache_audiotrack);
              }
              if (historySongId && historySongId !== level.song_id?.toString()) {
                updatesObj.song_id = historySongId;
              }
              if (historyGdHit.cache_username && historyGdHit.cache_username !== level.creator) {
                updatesObj.creator = historyGdHit.cache_username;
              }
            }
          }
          await new Promise(r => setTimeout(r, 20));
        } catch (err) { console.error(`History GD fetch failed for ${level.name}:`, err); }

        const aredl = aredlMap[String(level.level_id)];
        if (aredl) {
          if (!updatesObj.song_id && aredl.song !== undefined && aredl.song !== null && String(aredl.song) !== level.song_id?.toString()) {
            updatesObj.song_id = String(aredl.song);
          }
          if (aredl.description && aredl.description !== level.description) {
            updatesObj.description = aredl.description;
          }
        }

        if (Object.keys(updatesObj).length > 0) {
          const setClause = Object.keys(updatesObj).map(k => `${k} = ?`).join(', ');
          await c.env.DB.prepare(`UPDATE levels SET ${setClause} WHERE id = ?`).bind(...Object.values(updatesObj), level.id).run();
          updates.push({ id: level.id, name: level.name, changes: updatesObj });
        }
      }

      const updatedSongs = updates.filter(u => u.changes.song_id).length;
      const updatedDescs = updates.filter(u => u.changes.description).length;

      await c.env.DB.prepare(`UPDATE levels SET song_name = 'Newgrounds' WHERE CAST(song_id AS INTEGER) > 0 AND (song_name IS NULL OR song_name = '')`).run();
      for (let i = 0; i < GD_TRACKS.length; i++) {
        const trackNum = -(i + 1);
        await c.env.DB.prepare(`UPDATE levels SET song_name = ? WHERE song_id = ? AND (song_name IS NULL OR song_name = '')`).bind(GD_TRACKS[i], String(trackNum)).run();
      }

      return c.json({
        success: true,
        message: `Synced details for ${updates.length} levels (songs: ${updatedSongs}, descriptions: ${updatedDescs})`,
        updatedLevels: updates.length,
        details: updates.slice(0, 10)
      });
    } catch (error) {
      console.error('Level details sync error:', error);
      return c.json({ error: 'Failed to sync level details', details: error instanceof Error ? error.message : 'Unknown error' }, 500);
    }
  });

  // ── Fix Song Names ───────────────────────────────────

  app.post('/api/admin/fix-song-names', authenticateToken, async (c: any) => {
    try {
      const { batchSize = 10 } = await c.req.json().catch(() => ({}));
      const missing = await c.env.DB.prepare(
        `SELECT id, level_id, name FROM levels WHERE song_name = 'Newgrounds' LIMIT ?`
      ).bind(batchSize).all();
      const levels = missing.results || [];
      if (levels.length === 0) return c.json({ done: true, fixed: 0, remaining: 0 });

      let fixed = 0;
      const results: any[] = [];
      for (const level of levels) {
        try {
          const gdb = await fetch(`https://gdbrowser.com/api/level/${level.level_id}`);
          if (gdb.ok) {
            const data = await gdb.json() as any;
            if (data.songName) {
              await c.env.DB.prepare('UPDATE levels SET song_name = ? WHERE id = ?').bind(data.songName, level.id).run();
              fixed++;
              results.push({ name: level.name, songName: data.songName, status: 'ok' });
            } else {
              results.push({ name: level.name, status: 'no song name in response' });
            }
          } else {
            results.push({ name: level.name, status: `gdbrowser ${gdb.status}` });
          }
        } catch (err) {
          results.push({ name: level.name, status: String(err) });
        }
      }

      const totalRemaining = await c.env.DB.prepare(
        `SELECT COUNT(*) as cnt FROM levels WHERE song_name = 'Newgrounds'`
      ).first() as any;

      return c.json({ done: false, fixed, total: fixed + (totalRemaining?.cnt || 0), remaining: totalRemaining?.cnt || 0, results });
    } catch (error) {
      console.error('Fix song names error:', error);
      return c.json({ error: 'Failed' }, 500);
    }
  });
}
