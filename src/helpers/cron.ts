import { Bindings, HIDDEN_LEVEL_IDS } from '../types';

const MOTD_TYPE_PATTERNS: { regex: RegExp; type: string }[] = [
  { regex: /^MOTD\s+#?\d+/im, type: 'motd' },
  { regex: /^PLATFORMER\s+MOTD\s+#?\d+/im, type: 'platformer' },
  { regex: /^MOTW\s+Map\s+\d+/im, type: 'motw' },
  { regex: /^PLATFORMER\s+MOTW\s+Map\s+\d+/im, type: 'platformer_motw' },
  { regex: /^MOTM\s+Map\s+\d+/im, type: 'motm' },
  { regex: /^PLATFORMER\s+MOTM\s+Map\s+\d+/im, type: 'platformer_motm' },
  { regex: /^CURVE\s+MAP\s+#?\d+/im, type: 'curve' },
];

function detectMotdType(content: string): string | null {
  for (const pattern of MOTD_TYPE_PATTERNS) {
    if (pattern.regex.test(content)) return pattern.type;
  }
  return null;
}

export async function syncMotdFromDiscord(env: Bindings): Promise<{ types: Record<string, { levelId: string; message: string }> }> {
  const botToken = env.DISCORD_BOT_TOKEN;
  const channelId = env.DISCORD_CHANNEL_ID;
  const types: Record<string, { levelId: string; message: string }> = {};
  if (!botToken || !channelId) return { types };
  try {
    const response = await fetch(`https://discord.com/api/v10/channels/${channelId}/messages?limit=50`, {
      headers: { Authorization: `Bot ${botToken}` },
    });
    if (!response.ok) return { types };
    const messages = await response.json() as any[];
    if (!messages?.length) return { types };
    for (const msg of messages) {
      const content = msg.content || '';
      const type = detectMotdType(content);
      if (type && !types[type]) {
        const idMatch = content.match(/ID:\s*(\d+)/);
        if (idMatch) types[type] = { levelId: idMatch[1], message: content };
      }
    }
    return { types };
  } catch { return { types }; }
}

export async function saveMotdTypes(env: Bindings, types: Record<string, { levelId: string; message: string }>, updatedAt: string): Promise<string[]> {
  const typeKeys = Object.keys(types);
  for (const type of typeKeys) {
    const data = types[type];
    await env.DB.prepare(`
      INSERT INTO motd (id, message, updated_at, updated_by)
      VALUES (?, ?, ?, 'discord-bot')
      ON CONFLICT(id) DO UPDATE SET message = excluded.message, updated_at = excluded.updated_at, updated_by = excluded.updated_by
    `).bind(type, data.message, updatedAt).run();
  }
  return typeKeys;
}

export async function syncAredlRankings(env: Bindings): Promise<number> {
  const response = await fetch('https://api.aredl.net/v2/api/aredl/levels');
  if (!response.ok) throw new Error('Failed to fetch AREDL data');
  const aredlLevels = await response.json() as any[];

  const currentLevels = await env.DB.prepare('SELECT id, name, aredl_rank as aredlRank FROM levels').all();
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
      await env.DB.prepare(`
        UPDATE levels SET aredl_rank = ?, edel_enjoyment = ?, nlw_tier = ?, gddl_tier = ? WHERE id = ?
      `).bind(aredlData.position || aredlData.rank, aredlData.edel_enjoyment ?? null, aredlData.nlw_tier ?? null, aredlData.gddl_tier ?? null, levelInfo.id).run();
      updatedCount++;
    }
  }

  const sortedLevels = await env.DB.prepare(
    'SELECT id FROM levels WHERE aredl_rank IS NOT NULL AND (hidden IS NULL OR hidden != 1) ORDER BY aredl_rank ASC'
  ).all();
  let hkgdRank = 1;
  for (const level of (sortedLevels.results || [])) {
    await env.DB.prepare('UPDATE levels SET hkgd_rank = ? WHERE id = ?').bind(hkgdRank, (level as any).id).run();
    hkgdRank++;
  }

  const unrankedLevels = await env.DB.prepare(
    'SELECT id FROM levels WHERE aredl_rank IS NULL AND (hidden IS NULL OR hidden != 1) ORDER BY hkgd_rank ASC'
  ).all();
  for (const level of (unrankedLevels.results || [])) {
    await env.DB.prepare('UPDATE levels SET hkgd_rank = ? WHERE id = ?').bind(hkgdRank, (level as any).id).run();
    hkgdRank++;
  }

  await env.DB.prepare('UPDATE levels SET hkgd_rank = 0 WHERE hidden = 1').run();

  return updatedCount;
}

export async function initUserTables(db: D1Database): Promise<void> {
  const run = async (sql: string) => { try { await db.exec(sql); } catch (e) { console.error('DB init:', sql.slice(0, 60), e); } };
  await run("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, display_name TEXT, player_name TEXT, discord TEXT, email TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)");
  await run("CREATE TABLE IF NOT EXISTS notifications (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, type TEXT NOT NULL, title TEXT NOT NULL, message TEXT NOT NULL, read INTEGER DEFAULT 0, created_at TEXT NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)");
  await run("CREATE TABLE IF NOT EXISTS claims (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, level_id TEXT NOT NULL, level_name TEXT NOT NULL, record_date TEXT, status TEXT DEFAULT 'pending', created_at TEXT NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)");
  await run("CREATE TABLE IF NOT EXISTS reset_tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token TEXT UNIQUE NOT NULL, expires_at INTEGER NOT NULL, used INTEGER DEFAULT 0, created_at TEXT NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)");
  await run("ALTER TABLE records ADD COLUMN points REAL");
  await run("ALTER TABLE platformer_records ADD COLUMN points REAL");
  await run("ALTER TABLE claims ADD COLUMN player_name TEXT");
  await run("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0");
  await run("ALTER TABLE levels ADD COLUMN hidden INTEGER DEFAULT 0");
  for (const lid of HIDDEN_LEVEL_IDS) {
    await db.prepare('UPDATE levels SET hidden = 1 WHERE level_id = ?').bind(lid).run();
  }
}
