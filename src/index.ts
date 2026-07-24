import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { secureHeaders } from 'hono/secure-headers';
import { Bindings } from './types';
import { initUserTables, syncMotdFromDiscord, saveMotdTypes, syncAredlRankings } from './helpers/cron';
import { registerAuthRoutes } from './routes/auth';
import { registerAdminRoutes } from './routes/admin';
import { registerLevelRoutes } from './routes/levels';
import { registerPlatformerRoutes } from './routes/platformer';
import { registerSubmissionRoutes } from './routes/submissions';
import { registerContentRoutes } from './routes/content';
import { registerSyncRoutes } from './routes/sync';
import { registerMiscRoutes } from './routes/misc';

const app = new Hono<{ Bindings: Bindings }>();

app.use('*', logger());
app.use('*', secureHeaders());

app.use('*', cors({
  origin: (origin) => {
    const allowed = [
      'http://localhost:5173',
      'http://localhost:4173',
      'https://hkgd-website-frontend.hkgdl.workers.dev',
      'https://hkgd-frontend.hkgdl.workers.dev',
      'https://hkgdl.dpdns.org',
    ];
    if (!origin) return origin;
    try {
      const url = new URL(origin);
      if (allowed.some(a => new URL(a).origin === url.origin)) return origin;
      if (url.protocol === 'geode:') return origin;
    } catch { return null; }
    return null;
  },
  credentials: true,
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
}));

// Ensure DB tables exist on first request
let tablesInitialized = false;
app.use('*', async (c, next) => {
  if (!tablesInitialized) {
    await initUserTables(c.env.DB);
    tablesInitialized = true;
  }
  await next();
});

// API info
app.get('/api', (c) => {
  return c.json({
    name: 'HKGD API',
    version: '0.9.0',
    endpoints: {
      levels: '/api/levels',
      platformer: '/api/platformer-levels',
      auth: '/api/auth/login',
      pending: '/api/pending',
      changelog: '/api/changelog',
    }
  });
});

// Register all route modules
registerAuthRoutes(app);
registerAdminRoutes(app);
registerLevelRoutes(app);
registerPlatformerRoutes(app);
registerSubmissionRoutes(app);
registerContentRoutes(app);
registerSyncRoutes(app);
registerMiscRoutes(app);

// ── Export ───────────────────────────────────────────

export default {
  fetch: app.fetch,
  scheduled: async (controller: any, env: any, ctx: any) => {
    if (controller.cron === '0 1 * * *') {
      console.log('[Cron] Starting MOTD sync from Discord...');
      try {
        const result = await syncMotdFromDiscord(env);
        if (result && Object.keys(result.types).length > 0) {
          const updatedAt = new Date().toISOString();
          const typeKeys = await saveMotdTypes(env, result.types, updatedAt);
          console.log(`[Cron] MOTD synced: ${typeKeys.join(', ')}`);
        } else {
          console.error('[Cron] MOTD sync failed — no messages found');
        }
      } catch (e) {
        console.error('[Cron] MOTD sync error:', e);
      }
      return;
    }

    try {
      const updatedCount = await syncAredlRankings(env);
      console.log(`[Cron] AREDL auto-sync completed: ${updatedCount} levels updated`);
    } catch (e) {
      console.error('[Cron] AREDL sync error:', e);
    }
  }
};
