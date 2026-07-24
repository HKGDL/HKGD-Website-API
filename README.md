# HKGD Demon List API

Backend API for the HKGD Demon List (HKGDL) — a Geometry Dash demon list for the Hong Kong GD community.

## Stack

- **Runtime**: Cloudflare Workers
- **Framework**: Hono
- **Database**: Cloudflare D1 (SQLite)
- **Email**: Resend

## Setup

```bash
npm install
npm run dev
```

## Deploy

```bash
npm run deploy
```

Auto-deploys on push to `main`.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `JWT_SECRET` | Secret for JWT tokens |
| `ADMIN_PASSWORD` | Admin panel password |
| `RESEND_API_KEY` | Resend email API key |
| `SITE_URL` | Frontend URL (e.g. `https://hkgdl.dpdns.org`) |
| `GOOGLE_SHEETS_API_KEY` | Google Sheets API key for HKGD spreadsheet sync |
| `GOOGLE_SHEET_ID` | HKGD spreadsheet ID |
| `DISCORD_BOT_TOKEN` | Discord bot token for MOTD sync |
| `DISCORD_CHANNEL_ID` | Discord channel for MOTD |

## API Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/api/levels` | GET | List all levels |
| `/api/levels/:rank` | GET | Get level by rank |
| `/api/platformer` | GET | Platformer levels |
| `/api/leaderboard` | GET | Player leaderboard |
| `/api/user/register` | POST | Register account |
| `/api/user/login` | POST | Login |
| `/api/user/me` | GET | Get current user |
| `/api/user/profile` | PUT | Update profile |
| `/api/user/forgot-password` | POST | Request password reset |
| `/api/user/reset-password` | POST | Reset password |
| `/api/claims` | POST | Claim player profile |
| `/api/records` | POST | Submit record |
| `/api/admin/*` | * | Admin routes (requires auth) |
| `/api/sync/sheets` | POST | Sync from Google Sheets |
| `/api/sync/aredl` | POST | Sync from AREDL |

## Structure

```
api/
├── src/
│   ├── index.ts          # Entry point, CORS, routes
│   ├── types.ts          # TypeScript types
│   ├── env.d.ts          # Cloudflare env types
│   ├── helpers/
│   │   ├── auth.ts       # JWT auth middleware
│   │   ├── email.ts      # Email templates & sending
│   │   ├── ipban.ts      # IP ban & SQL injection detection
│   │   └── cron.ts       # Scheduled tasks
│   └── routes/
│       ├── auth.ts       # User auth routes
│       ├── admin.ts      # Admin routes
│       ├── levels.ts     # Level data
│       ├── submissions.ts # Record submissions
│       ├── sync.ts       # Google Sheets & AREDL sync
│       ├── content.ts    # Changelog, MOTD
│       └── misc.ts       # Notifications, misc
├── schema.sql            # Database schema
├── wrangler.toml         # Cloudflare config
└── GUIDELINES.md         # Submission guidelines
```
