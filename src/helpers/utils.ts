export function getClientIP(c: any): string {
  let ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ||
           c.req.header('x-real-ip')?.trim() ||
           '127.0.0.1';
  if (ip === '::1' || ip === '::ffff:127.0.0.1') ip = '127.0.0.1';
  if (ip.startsWith('::ffff:')) ip = ip.substring(7);
  return ip || '127.0.0.1';
}

export function computePoints(rank: number, totalLevels: number): number {
  if (!totalLevels || totalLevels <= 0) return 1;
  if (rank <= 0) rank = 1;
  if (rank > totalLevels) rank = totalLevels;
  return Math.max(1, Math.round(500 * (1 - Math.log10(rank) / Math.log10(totalLevels))));
}

export async function createNotification(db: D1Database, userId: string, type: string, title: string, message: string): Promise<void> {
  const id = `notif-${crypto.randomUUID()}`;
  const now = new Date().toISOString();
  await db.prepare(`
    INSERT INTO notifications (id, user_id, type, title, message, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(id, userId, type, title, message, now).run();
}
