// ... (rest of your file remains unchanged)
export default {
  fetch: app.fetch,
  scheduled: async (controller: any, env: any, ctx: any) => {
    // MOTD sync from Discord at 18:00 UTC (02:00 GMT+8)
    if (controller.cron === '0 18 * * *') {
      console.log('[Cron] Starting MOTD sync from Discord...');
      const result = await syncMotdFromDiscord(env);
      if (result) {
        const updatedAt = new Date().toISOString();
        await env.DB.prepare(`
          INSERT INTO motd (id, message, updated_at, updated_by)
          VALUES ('main', ?, ?, 'discord-bot')
          ON CONFLICT(id) DO UPDATE SET
            message = excluded.message,
            updated_at = excluded.updated_at,
            updated_by = excluded.updated_by
        `).bind(result.levelId, updatedAt).run();
        console.log(`[Cron] MOTD synced to level ID ${result.levelId}`);
      } else {
        console.error('[Cron] MOTD sync failed');
      }
      return;
    }

    const response = await fetch(`https://api.aredl.net/v2/api/aredl/levels`);
    if (!response.ok) {
      console.error('AREDL sync failed: Failed to fetch AREDL data');
      return;
    }
    const aredlLevels = await response.json() as any[];
    
    const currentLevels = await env.DB.prepare(`
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
    
    const aredlDataMap = new Map<string, any>();
    for (const aredlLevel of aredlLevels) {
      const name = aredlLevel.name?.toLowerCase().trim();
      if (name) {
        aredlDataMap.set(name, aredlLevel);
      }
    }
    // ... (rest of your scheduled handler remains unchanged)
}
