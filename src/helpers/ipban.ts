export const MAX_LOGIN_ATTEMPTS = 5;
export const BAN_DURATION = 15 * 60 * 1000;
export const SQL_INJECTION_BAN_DURATION = 24 * 60 * 60 * 1000;

const SQL_INJECTION_PATTERNS = [
  /(\bOR\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?)/i,
  /(\bAND\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?)/i,
  /(['"])\s*(OR|AND)\s+['"]?\1\s*=\s*\1/i,
  /(\bUNION\b\s+\bSELECT\b)/i,
  /(\bDROP\b\s+\bTABLE\b)/i,
  /(\bINSERT\b\s+\bINTO\b)/i,
  /(\bDELETE\b\s+\bFROM\b)/i,
  /(\bUPDATE\b\s+\w+\s+\bSET\b)/i,
  /(['"])\s*;\s*(DROP|DELETE|INSERT|UPDATE|SELECT|ALTER)/i,
  /--\s*$/,
  /\/\*[\s\S]*\*\//,
  /(\bSLEEP\b\s*\()/i,
  /(\bBENCHMARK\b\s*\()/i,
  /['"]\s*;\s*['"]\s*=\s*['"]/i,
  /(0x[0-9a-fA-F]+)/,
  /(\bCONCAT\b\s*\()/i,
  /(CHAR\s*\(\s*\d+)/i,
];

export function detectSqlInjection(value: string): boolean {
  if (!value) return false;
  const decoded = decodeURIComponent(value);
  const inputs = [value, decoded];
  for (const input of inputs) {
    for (const pattern of SQL_INJECTION_PATTERNS) {
      if (pattern.test(input)) return true;
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
