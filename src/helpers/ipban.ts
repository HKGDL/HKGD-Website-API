export const MAX_LOGIN_ATTEMPTS = 5;
export const BAN_DURATION = 15 * 60 * 1000;
export const SQL_INJECTION_BAN_DURATION = 24 * 60 * 60 * 1000;

const SQL_INJECTION_PATTERNS = [
  /['"]\s*(?:OR|AND)\s+['"]\d+['"]\s*=\s*['"]\d+['"]/i,
  /['"]\s*(?:OR|AND)\s+['"]\s*=\s*['"]/i,
  /;\s*(?:DROP|DELETE|INSERT|UPDATE|SELECT|ALTER)\b/i,
  /\bUNION\s+(?:ALL\s+)?SELECT\b/i,
  /\bDROP\s+TABLE\b/i,
  /--\s*$/,
  /\/\*[\s\S]+\*\//,
  /\bSLEEP\s*\(\s*\d+\s*\)/i,
  /\bBENCHMARK\s*\(\s*\d+/i,
  /\bWAITFOR\s+DELAY\b/i,
];

export function detectSqlInjection(value: string): boolean {
  if (!value) return false;
  try {
    const decoded = decodeURIComponent(value);
    for (const pattern of SQL_INJECTION_PATTERNS) {
      if (pattern.test(value) || pattern.test(decoded)) return true;
    }
  } catch {
    for (const pattern of SQL_INJECTION_PATTERNS) {
      if (pattern.test(value)) return true;
    }
  }
  return false;
}

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

export async function banForSqlInjection(db: D1Database, ip: string): Promise<void> {
  const bannedUntil = Date.now() + SQL_INJECTION_BAN_DURATION;
  await db.prepare(`
    INSERT INTO ip_bans (ip, attempts, banned_until, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET
      attempts = excluded.attempts,
      banned_until = excluded.banned_until,
      updated_at = excluded.updated_at
  `).bind(ip, MAX_LOGIN_ATTEMPTS + 1, bannedUntil, Date.now()).run();
}
