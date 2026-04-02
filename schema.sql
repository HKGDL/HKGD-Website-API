-- HKGD D1 Database Schema
-- Compatible with Cloudflare D1 (SQLite)

-- Levels table
CREATE TABLE IF NOT EXISTS levels (
  id TEXT PRIMARY KEY,
  hkgd_rank INTEGER,
  aredl_rank INTEGER,
  pemonlist_rank INTEGER,
  name TEXT NOT NULL,
  creator TEXT NOT NULL,
  verifier TEXT NOT NULL,
  level_id TEXT NOT NULL,
  description TEXT,
  thumbnail TEXT,
  list_points REAL NOT NULL DEFAULT 0,
  song_id TEXT,
  song_name TEXT,
  tags TEXT,
  date_added TEXT,
  pack TEXT,
  gddl_tier INTEGER,
  nlw_tier TEXT,
  edel_enjoyment REAL
);

-- Records table
CREATE TABLE IF NOT EXISTS records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  level_id TEXT NOT NULL,
  player TEXT NOT NULL,
  date TEXT NOT NULL,
  video_url TEXT,
  fps TEXT,
  cbf INTEGER DEFAULT 0,
  attempts INTEGER,
  mode TEXT DEFAULT 'classic',
  FOREIGN KEY (level_id) REFERENCES levels(id) ON DELETE CASCADE
);

-- Changelog table
CREATE TABLE IF NOT EXISTS changelog (
  id TEXT PRIMARY KEY,
  date TEXT NOT NULL,
  level_name TEXT NOT NULL,
  level_id TEXT NOT NULL,
  change_type TEXT NOT NULL,
  old_rank INTEGER,
  new_rank INTEGER,
  description TEXT NOT NULL,
  list_type TEXT DEFAULT 'classic'
);

-- Members table
CREATE TABLE IF NOT EXISTS members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  country TEXT,
  total_points REAL NOT NULL DEFAULT 0,
  levels_beaten INTEGER NOT NULL DEFAULT 0,
  avatar TEXT
);

-- Pending submissions table
CREATE TABLE IF NOT EXISTS pending_submissions (
  id TEXT PRIMARY KEY,
  level_id TEXT NOT NULL,
  level_name TEXT,
  is_new_level INTEGER DEFAULT 0,
  record_data TEXT NOT NULL,
  level_data TEXT,
  submitted_at TEXT NOT NULL,
  submitted_by TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
);

-- Website content table
CREATE TABLE IF NOT EXISTS website_content (
  id TEXT PRIMARY KEY,
  content_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- IP Bans table (for login attempt tracking)
CREATE TABLE IF NOT EXISTS ip_bans (
  ip TEXT PRIMARY KEY,
  attempts INTEGER DEFAULT 0,
  banned_until INTEGER DEFAULT 0,
  updated_at INTEGER
);

-- Settings table (for site-wide settings)
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_levels_hkgd_rank ON levels(hkgd_rank);
CREATE INDEX IF NOT EXISTS idx_records_level_id ON records(level_id);
CREATE INDEX IF NOT EXISTS idx_changelog_date ON changelog(date DESC);
CREATE INDEX IF NOT EXISTS idx_members_levels ON members(levels_beaten DESC);