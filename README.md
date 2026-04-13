# HKGD Demon List API

A Cloudflare Workers API for the Hong Kong Geometry Dash Demon List, built with Hono and D1 database.

## Features

- **Levels Management** - CRUD operations for demon levels with AREDL rankings
- **Records Tracking** - Player records with video links, FPS, CBF, and attempts
- **Members Directory** - HKGD community member listings
- **Changelog** - Track level ranking changes over time
- **Content Management** - Dynamic website content configuration
- **Pending Submissions** - User-submitted records for admin review
- **AREDL Sync** - Automatic ranking sync with AREDL (A Regular Extreme Demon List)
- **Platformer Proxy** - Proxies platformer demon data from Pemonlist API
- **Authentication** - JWT-based admin auth with IP ban protection

## Tech Stack

- **Runtime**: Cloudflare Workers
- **Framework**: [Hono](https://hono.dev/) v4
- **Database**: Cloudflare D1 (SQLite)
- **Auth**: JWT (jose library)

## API Endpoints

### Authentication
- `POST /api/auth/login` - Admin login (with IP-based rate limiting)
- `POST /api/auth/verify` - Verify JWT token
- `POST /api/auth/logout` - Logout

### Public Routes
- `GET /api/levels` - Get all levels with records
- `GET /api/levels/:id` - Get single level by ID
- `GET /api/members` - Get all members
- `GET /api/changelog` - Get changelog entries
- `GET /api/content` - Get website content configuration
- `GET /api/pending-submissions` - Get pending submissions
- `GET /api/platformer-demons` - Proxy to Pemonlist API
- `GET /api/settings` - Get public settings
- `GET /api/health` - Health check

### Admin Routes (requires JWT authentication)
- `POST /api/levels` - Create level
- `PUT /api/levels/:id` - Update level
- `DELETE /api/levels/:id` - Delete level
- `POST /api/levels/:levelId/records` - Add record to level
- `PUT /api/records/:recordId` - Update record
- `DELETE /api/records/:recordId` - Delete record
- `POST /api/changelog` - Create changelog entry
- `DELETE /api/changelog/:id` - Delete changelog entry
- `POST /api/content` - Update website content
- `PUT /api/settings/:key` - Update setting
- `POST /api/aredl-sync` - Sync rankings with AREDL
- `GET /api/ip-bans` - List IP bans
- `DELETE /api/ip-bans/:ip` - Unban IP address

### Submission Routes
- `POST /api/pending-submissions` - Create new submission (public)
- `PUT /api/pending-submissions/:id` - Update submission status (admin)

## Development

```bash
# Install dependencies
npm install

# Start local development (port 8787)
npm run dev

# Run database migrations locally
npm run db:migrate

# Seed database with initial data
npm run db:seed
```

## Deployment

```bash
# Deploy to Cloudflare Workers
npm run deploy

# Run database migrations on remote
npm run db:migrate:remote
```

The API is deployed at:
- `api.hkgdl.dpdns.org`
- `hkgdl.dpdns.org/api`

## Environment Configuration

### Secrets (set via `wrangler secret put`)
- `JWT_SECRET` - Secret key for JWT signing
- `ADMIN_PASSWORD` - Password for admin authentication

### Variables (in `wrangler.toml`)
- `ENVIRONMENT` - Environment name (development/production)

## Database Schema

### Tables

| Table | Description |
|-------|-------------|
| `levels` | Demon levels with rankings (HKGD, AREDL, Pemonlist) |
| `records` | Player completion records |
| `members` | HKGD community members |
| `changelog` | Level ranking change history |
| `pending_submissions` | User-submitted records awaiting approval |
| `website_content` | Dynamic website content (JSON) |
| `ip_bans` | IP addresses banned from login attempts |
| `settings` | Site-wide boolean settings |

### Key Indexes
- `idx_levels_hkgd_rank` - Levels ordered by HKGD rank
- `idx_records_level_id` - Records by level
- `idx_changelog_date` - Changelog by date
- `idx_members_levels` - Members by levels beaten

See `schema.sql` for the complete database structure.

## Security

- **IP Ban System**: After 5 failed login attempts, IPs are banned for 15 minutes
- **JWT Tokens**: 2-hour expiration with secure signing
- **CORS**: Restricted to allowed origins
- **Secure Headers**: Enabled via Hono middleware

## Scripts

- `npm run db:export` - Export database data for backup

## License

[DBAD](./DBAD.md)
