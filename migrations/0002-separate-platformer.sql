-- Migration: Separate platformer demons into dedicated tables

-- Create platformer_levels table
CREATE TABLE IF NOT EXISTS platformer_levels (
    id TEXT PRIMARY KEY,
    hkgd_rank INTEGER,
    pemonlist_rank INTEGER,
    name TEXT NOT NULL,
    creator TEXT NOT NULL,
    verifier TEXT,
    level_id TEXT,
    description TEXT,
    thumbnail TEXT,
    song_id TEXT,
    song_name TEXT,
    tags TEXT,
    date_added TEXT,
    pack TEXT,
    difficulty INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Create platformer_records table
CREATE TABLE IF NOT EXISTS platformer_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level_id TEXT NOT NULL,
    player TEXT NOT NULL,
    date TEXT NOT NULL,
    video_url TEXT,
    fps TEXT,
    cbf INTEGER DEFAULT 0,
    attempts INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (level_id) REFERENCES platformer_levels(id) ON DELETE CASCADE
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_platformer_records_level_id ON platformer_records(level_id);

-- Migrate platformer levels from levels table
INSERT INTO platformer_levels (id, hkgd_rank, pemonlist_rank, name, creator, verifier, level_id, description, thumbnail, song_id, song_name, tags, date_added, pack)
SELECT 
    id, 
    hkgd_rank, 
    pemonlist_rank, 
    name, 
    creator, 
    verifier, 
    level_id, 
    description, 
    thumbnail, 
    song_id, 
    song_name, 
    tags, 
    date_added, 
    pack
FROM levels 
WHERE pemonlist_rank IS NOT NULL OR tags LIKE '%"Platformer"%';

-- Migrate records for platformer levels
INSERT INTO platformer_records (level_id, player, date, video_url, fps, cbf, attempts)
SELECT r.level_id, r.player, r.date, r.video_url, r.fps, r.cbf, r.attempts
FROM records r
INNER JOIN platformer_levels pl ON r.level_id = pl.id;

-- Remove platformer levels from main levels table
DELETE FROM levels WHERE pemonlist_rank IS NOT NULL OR tags LIKE '%"Platformer"%';

-- Remove orphaned records
DELETE FROM records WHERE level_id NOT IN (SELECT id FROM levels);