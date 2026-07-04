export type Bindings = {
  DB: D1Database;
  ENVIRONMENT: string;
  JWT_SECRET: string;
  ADMIN_PASSWORD: string;
  SUGGESTIONS_PASSWORD: string;
  MOTD_ADMIN_PASSWORD: string;
  INDEXNOW_KEY: string;
  SITE_HOSTNAME: string;
  GOOGLE_SHEETS_API_KEY?: string;
  GOOGLE_SHEET_ID?: string;
  GOOGLE_SHEET_RANGE?: string;
  DISCORD_BOT_TOKEN?: string;
  DISCORD_CHANNEL_ID?: string;
  RESEND_API_KEY?: string;
  SITE_URL?: string;
};

export const HIDDEN_LEVEL_IDS = ['118026710', '79410525', '93093815', '113459504', '109795047', '125385088'];

export function safe(v: any) {
  return v === undefined ? null : v;
}
