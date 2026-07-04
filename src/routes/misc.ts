import { Hono } from 'hono';
import { Bindings } from '../types';

export function registerMiscRoutes(app: Hono<{ Bindings: Bindings }>) {
  // ── GDBrowser / History GD Proxy ─────────────────────

  app.get('/api/gdbrowser/level/:levelId', async (c) => {
    try {
      const levelId = c.req.param('levelId');
      const response = await fetch(`https://history.geometrydash.eu/api/v1/search/level/advanced/?query=${levelId}&limit=1&filter=online_id%3D${levelId}`);
      if (response.ok) {
        const data = await response.json() as any;
        if (data.hits && data.hits.length > 0) return c.json(data.hits[0]);
        return c.json({ error: 'Level not found' }, 404);
      }
      const gdbResponse = await fetch(`https://www.gdbrowser.com/api/level/${levelId}?key=Wmfd2893gb7`, {
        headers: { 'User-Agent': '', 'Accept': 'application/json' },
      });
      const gdbData = await gdbResponse.text();
      if (gdbData.startsWith('<') || gdbData.startsWith('-1') || gdbData.startsWith('Not Found')) {
        return c.json({ error: 'Level not found' }, 404);
      }
      try { return c.json(JSON.parse(gdbData)); } catch { return c.json({ error: 'Invalid response' }, 500); }
    } catch (error) {
      console.error('Error fetching level:', error);
      return c.json({ error: 'Failed to fetch level' }, 500);
    }
  });

  app.get('/api/gdbrowser/search', async (c) => {
    try {
      const query = c.req.query('q');
      if (!query) return c.json({ error: 'Query required' }, 400);
      const filter = 'cache_length=5';
      const response = await fetch(`https://history.geometrydash.eu/api/v1/search/level/advanced/?query=${encodeURIComponent(query)}&limit=20&filter=${encodeURIComponent(filter)}`);
      if (response.ok) {
        const data = await response.json() as any;
        return c.json(data.hits || []);
      }
      return c.json({ error: 'Search failed' }, 500);
    } catch (error) {
      console.error('Error searching:', error);
      return c.json({ error: 'Failed to search' }, 500);
    }
  });

  // ── Health ───────────────────────────────────────────

  app.get('/api/health', (c) => c.json({ status: 'ok', timestamp: new Date().toISOString() }));
}
