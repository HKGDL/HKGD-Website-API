# HKGD API

Backend API for the HKGD (Hong Kong Geometry Dash) Demon List.

## Tech Stack

- **Runtime**: Node.js 18+
- **Framework**: Express.js 5
- **Database**: SQLite (better-sqlite3)
- **Authentication**: JWT (jsonwebtoken)
- **Security**: Helmet.js, express-rate-limit, express-validator

## Quick Start

```bash
# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Start server
npm start
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | JWT signing secret | hkgd-secret-key-2024 |
| `ADMIN_PASSWORD` | Admin password | hkgdadmin2024 |
| `PORT` | HTTP port | 19132 |
| `HTTPS_PORT` | HTTPS port | 19133 |
| `ALLOWED_ORIGINS` | CORS origins | http://localhost:5173,https://hkgdl.ddns.net |
| `SSL_KEY_PATH` | SSL key path | ./certs/key.pem |
| `SSL_CERT_PATH` | SSL cert path | ./certs/cert.pem |
| `TRUST_PROXY` | Trust proxy | false |

## API Endpoints

### Authentication
- `POST /api/auth/login` - Admin login
- `POST /api/auth/verify` - Verify token
- `POST /api/auth/logout` - Logout

### Levels
- `GET /api/levels` - Get all levels
- `GET /api/levels/:id` - Get level by ID
- `POST /api/levels` - Create level (admin)
- `PUT /api/levels/:id` - Update level (admin)
- `DELETE /api/levels/:id` - Delete level (admin)
- `POST /api/levels/:id/records` - Add record (admin)

### Members
- `GET /api/members` - Get all members

### Changelog
- `GET /api/changelog` - Get changelog
- `POST /api/changelog` - Add entry (admin)
- `DELETE /api/changelog/:id` - Delete entry (admin)
- `DELETE /api/changelog` - Clear all (admin)

### Submissions
- `GET /api/pending-submissions` - Get pending submissions
- `POST /api/pending-submissions` - Create submission
- `PUT /api/pending-submissions/:id` - Approve/reject (admin)

### External
- `GET /api/platformer-demons` - Proxy to Pemonlist API
- `POST /api/aredl-sync` - Sync with AREDL (admin)
- `GET /api/content` - Get website content
- `POST /api/content` - Save website content (admin)

## Security Features

- JWT authentication with httpOnly cookies
- Rate limiting on auth and submission endpoints
- IP banning after failed login attempts
- Helmet.js headers
- Input validation with express-validator
- SQL injection protection (prepared statements)

## SSL Certificates

For HTTPS in production, generate self-signed certificates:

```bash
# Linux/Mac
./generate-certs.sh

# Windows
generate-cert.bat
```

Or use Let's Encrypt for production certificates.

## License

[Dont Be A Dick (DBAD) Public License](DBAD.md)
