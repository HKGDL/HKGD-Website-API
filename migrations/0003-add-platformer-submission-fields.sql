-- Migration: Add platformer submission fields to pending_submissions table
-- This adds support for platformer submissions where admin decides difficulty placement

-- Add is_platformer column if it doesn't exist
ALTER TABLE pending_submissions ADD COLUMN IF NOT EXISTS is_platformer INTEGER DEFAULT 0;

-- Add admin_decides_difficulty column if it doesn't exist
ALTER TABLE pending_submissions ADD COLUMN IF NOT EXISTS admin_decides_difficulty INTEGER DEFAULT 0;

-- Create index for platformer submissions for faster querying
CREATE INDEX IF NOT EXISTS idx_pending_submissions_platformer ON pending_submissions(is_platformer);

-- Create index for admin decision submissions
CREATE INDEX IF NOT EXISTS idx_pending_submissions_admin_decides ON pending_submissions(admin_decides_difficulty);
