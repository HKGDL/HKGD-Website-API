import { Hono } from 'hono';
import { Bindings, safe } from '../types';
import { createNotification, computePoints } from '../helpers/utils';
import { notifyContentChanged } from '../helpers/indexnow';

export function registerSubmissionRoutes(app: Hono<{ Bindings: Bindings }>) {
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
      const { id, levelId, levelName, isNewLevel, record, record_data, level_data, submittedAt, submittedBy, status, aredlRank } = data;
      const actualRecordData = record_data || JSON.stringify(record);
      const actualLevelData = level_data ? JSON.stringify(level_data) : null;

      await c.env.DB.prepare(`
        INSERT INTO pending_submissions (id, level_id, level_name, is_new_level, record_data, level_data, submitted_at, submitted_by, status, aredl_rank)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(id, levelId, levelName, isNewLevel ? 1 : 0, actualRecordData, actualLevelData, submittedAt, submittedBy, status || 'pending', aredlRank ?? null).run();

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
      const { status, adminNotes } = await c.req.json();
      if (!['pending', 'approved', 'rejected'].includes(status)) return c.json({ error: 'Invalid status' }, 400);

      await c.env.DB.prepare('UPDATE pending_submissions SET status = ?, admin_notes = ? WHERE id = ?').bind(status, adminNotes || null, id).run();

      if (status === 'approved') {
        const sub = await c.env.DB.prepare('SELECT * FROM pending_submissions WHERE id = ?').bind(id).first() as any;
        if (sub) {
          let level = await c.env.DB.prepare('SELECT id FROM levels WHERE level_id = ?').bind(sub.level_id).first();
          if (!level) {
            const now = new Date().toISOString().split('T')[0];
            let creator = 'Unknown';
            let verifier = 'Unknown';
            let aredlRank = sub.aredl_rank;
            if (!aredlRank) {
              try {
                const aredlRes = await fetch('https://api.aredl.net/v2/api/aredl/levels?page=1&limit=2000');
                if (aredlRes.ok) {
                  const aredlData = await aredlRes.json() as any[];
                  const match = aredlData.find((l: any) => String(l.level_id) === String(sub.level_id));
                  if (match) {
                    aredlRank = match.position || match.rank || null;
                    creator = match.creator || creator;
                    verifier = match.verifier || verifier;
                  }
                }
              } catch {}
            } else {
              try {
                const aredlRes = await fetch(`https://api.aredl.net/v2/api/aredl/levels?page=1&limit=2000`);
                if (aredlRes.ok) {
                  const aredlData = await aredlRes.json() as any[];
                  const match = aredlData.find((l: any) => Number(l.position) === Number(aredlRank) || String(l.level_id) === String(sub.level_id));
                  if (match) {
                    creator = match.creator || creator;
                    verifier = match.verifier || verifier;
                  }
                }
              } catch {}
            }
            if (creator === 'Unknown' || verifier === 'Unknown') {
              try {
                const hgRes = await fetch(
                  `https://history.geometrydash.eu/api/v1/search/level/advanced/?query=${sub.level_id}&limit=1&filter=online_id%3D${sub.level_id}`
                );
                if (hgRes.ok) {
                  const hgData = await hgRes.json() as any;
                  const hit = hgData.hits?.[0];
                  if (hit) {
                    if (hit.cache_username) creator = hit.cache_username;
                    if (hit.cache_username) verifier = hit.cache_username;
                  }
                }
              } catch {}
            }
            await c.env.DB.prepare(`
              INSERT INTO levels (id, level_id, name, creator, verifier, tags, date_added, thumbnail)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `).bind(sub.level_id, sub.level_id, sub.level_name, creator, verifier, '["Overall"]', now, `https://levelthumbs.prevter.me/thumbnail/${sub.level_id}`).run();
            if (aredlRank) {
              await c.env.DB.prepare('UPDATE levels SET aredl_rank = ? WHERE id = ?').bind(aredlRank, sub.level_id).run();
              const beforeCount = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM levels WHERE aredl_rank IS NOT NULL AND aredl_rank < ?').bind(aredlRank).first() as any;
              const hkgdRank = (beforeCount?.cnt || 0) + 1;
              await c.env.DB.prepare('UPDATE levels SET hkgd_rank = ? WHERE id = ?').bind(hkgdRank, sub.level_id).run();
            } else {
              const maxRank = await c.env.DB.prepare('SELECT MAX(hkgd_rank) as maxRank FROM levels').first() as any;
              await c.env.DB.prepare('UPDATE levels SET hkgd_rank = ? WHERE id = ?').bind((maxRank?.maxRank || 0) + 1, sub.level_id).run();
            }
          }

          const recordData = sub.record_data ? (typeof sub.record_data === 'string' ? JSON.parse(sub.record_data) : sub.record_data) : null;

          let recordPoints = null;
          const levelInfo = await c.env.DB.prepare('SELECT hkgd_rank FROM levels WHERE id = ?').bind(sub.level_id).first() as any;
          if (levelInfo && levelInfo.hkgd_rank) {
            const totalRanked = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM levels WHERE hkgd_rank IS NOT NULL AND hkgd_rank > 0').first() as any;
            recordPoints = computePoints(levelInfo.hkgd_rank, (totalRanked as any)?.cnt || 0);
          }

          await c.env.DB.prepare(`
            INSERT INTO records (level_id, player, date, video_url, fps, points)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(sub.level_id, recordData?.player || sub.submitted_by, sub.submitted_at, recordData?.videoUrl || null, recordData?.fps ? String(recordData.fps) : null, recordPoints).run();

          const submitter = sub.submitted_by;
          if (submitter) {
            const user = await c.env.DB.prepare('SELECT id FROM users WHERE player_name = ? OR username = ?').bind(submitter, submitter).first() as any;
            if (user) {
              await createNotification(c.env.DB, user.id, 'submission_approved',
                'Record Accepted',
                `Your record on ${sub.level_name} has been accepted!`
              );
            }
          }
        }
      } else if (status === 'rejected') {
        const sub = await c.env.DB.prepare('SELECT * FROM pending_submissions WHERE id = ?').bind(id).first() as any;
        if (sub) {
          const submitter = sub.submitted_by;
          if (submitter) {
            const user = await c.env.DB.prepare('SELECT id FROM users WHERE player_name = ? OR username = ?').bind(submitter, submitter).first() as any;
            if (user) {
              await createNotification(c.env.DB, user.id, 'submission_rejected',
                'Record Rejected',
                `Your record on ${sub.level_name} has been rejected.`
              );
            }
          }
        }
      }

      return c.json({ success: true, message: 'Submission updated successfully' });
    } catch (error) {
      console.error('Error updating submission:', error);
      return c.json({ error: 'Failed to update submission' }, 500);
    }
  });
}
