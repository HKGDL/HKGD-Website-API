-- Migration: Add platformer submission fields to pending_submissions table
-- This adds support for platformer submissions where admin decides difficulty placement

-- Add is_platformer column
ALTER TABLE pending_submissions ADD COLUMN is_platformer INTEGER DEFAULT 0;

-- Add admin_decides_difficulty column
ALTER TABLE pending_submissions ADD COLUMN admin_decides_difficulty INTEGER DEFAULT 0;

-- Create index for platformer submissions for faster querying
CREATE INDEX idx_pending_submissions_platformer ON pending_submissions(is_platformer);

-- Create index for admin decision submissions
CREATE INDEX idx_pending_submissions_admin_decides ON pending_submissions(admin_decides_difficulty);
