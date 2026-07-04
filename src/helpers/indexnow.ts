import { Bindings } from '../types';

const INDEXNOW_SEARCH_ENGINES = ['https://www.bing.com/indexnow'];

async function submitUrlsBatchToIndexNow(env: Bindings, urls: string[]): Promise<void> {
  const key = env.INDEXNOW_KEY;
  if (!key || urls.length === 0) return;
  const hostname = env.SITE_HOSTNAME || 'hkgdl.dpdns.org';
  const siteUrls = urls.map(u => u.startsWith('http') ? u : `https://${hostname}${u}`);
  const payload = { host: hostname, key, urlList: siteUrls };
  for (const engine of INDEXNOW_SEARCH_ENGINES) {
    try {
      await fetch(engine, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
        body: JSON.stringify(payload),
      });
    } catch {}
  }
}

export function notifyContentChanged(env: Bindings, extraUrls?: string[]) {
  const urls: string[] = ['/'];
  if (extraUrls) urls.push(...extraUrls);
  submitUrlsBatchToIndexNow(env, urls).catch(() => {});
}
