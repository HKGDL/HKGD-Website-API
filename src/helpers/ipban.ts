export const MAX_LOGIN_ATTEMPTS = 5;
export const BAN_DURATION = 15 * 60 * 1000;

export async function isIPBanned(db: D1Database, ip: string): Promise<{ banned: boolean; remainingTime?: number }> {
  const result = await db.prepare(
    'SELECT banned_until FROM ip_bans WHERE ip = ? AND banned_until > ?'
  ).bind(ip, Date.now()).first();
  if (result) {
    return { banned: true, remainingTime: Math.ceil((result.banned_until as number - Date.now()) / 1000) };
  }
  return { banned: false };
}

export async function recordFailedLogin(db: D1Database, ip: string): Promise<number> {
  const existing = await db.prepare('SELECT attempts FROM ip_bans WHERE ip = ?').bind(ip).first();
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

export async function resetFailedAttempts(db: D1Database, ip: string): Promise<void> {
  await db.prepare('DELETE FROM ip_bans WHERE ip = ?').bind(ip).run();
}
