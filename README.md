# HKGD Demon List API

A Cloudflare Workers API for the Hong Kong Geometry Dash Demon List, built with Hono and D1 database.

## Features

- **Levels Management** - CRUD operations for demon levels with rankings
- **Records Tracking** - Player records with video links, FPS, CBF, and attempts
- **Members Directory** - HKGD community member listings
- **Changelog** - Track level ranking changes over time
- **Content Management** - Dynamic website content configuration
- **Pending Submissions** - User-submitted records for admin review
- **AREDL Sync** - Automatic ranking sync with AREDL (A Regular Extreme Demon List)
- **Authentication** - JWT-based admin auth with IP ban protection

## Tech Stack

- **Runtime**: Cloudflare Workers
- **Framework**: [Hono](https://hono.dev/)
- **Database**: Cloudflare D1 (SQLite)
- **Auth**: JWT (jose library)

## API Endpoints

### Public Routes
- `GET /api/levels` - Get all levels with records
- `GET /api/levels/:id` - Get single level
- `GET /api/members` - Get all members
- `GET /api/changelog` - Get changelog entries
- `GET /api/content` - Get website content
- `GET /api/pending-submissions` - Get pending submissions
- `GET /api/platformer-demons` - Proxy to pemonlist API
- `GET /api/settings` - Get public settings
- `GET /api/health` - Health check

### Admin Routes (requires authentication)
- `POST /api/auth/login` - Admin login
- `POST /api/auth/verify` - Verify JWT token
- `POST /api/levels` - Create level
- `PUT /api/levels/:id` - Update level
- `DELETE /api/levels/:id` - Delete level
- `POST /api/levels/:levelId/records` - Add record
- `PUT /api/records/:recordId` - Update record
- `DELETE /api/records/:recordId` - Delete record
- `POST /api/changelog` - Create changelog entry
- `DELETE /api/changelog/:id` - Delete changelog entry
- `POST /api/content` - Update website content
- `PUT /api/settings/:key` - Update setting
- `POST /api/aredl-sync` - Sync rankings with AREDL

## Development

```bash
# Install dependencies
npm install

# Start local development
npm run dev

# Run database migrations locally
npm run db:migrate
```

## Deployment

```bash
# Deploy to Cloudflare Workers
npm run deploy

# Run database migrations on remote
npm run db:migrate:remote
```

## Environment Variables

Configure in `wrangler.toml` or Cloudflare dashboard:

- `JWT_SECRET` - Secret key for JWT signing
- `ADMIN_PASSWORD` - Password for admin authentication
- `ENVIRONMENT` - Environment name (development/production)

## Database Schema

See `schema.sql` for the complete database structure.

## License

MIT
