-- Migration: Add MOTD (Message of the Day) table
-- Allows admins to set a message shown to users on the website

CREATE TABLE IF NOT EXISTS motd (
    id TEXT PRIMARY KEY DEFAULT 'main',
    message TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_by TEXT
);
