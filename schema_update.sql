-- Add player mappings table
CREATE TABLE IF NOT EXISTS player_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    game_name TEXT NOT NULL,
    db_name TEXT NOT NULL,
    account_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(game_name, db_name)
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_player_mappings_game_name ON player_mappings(game_name);
CREATE INDEX IF NOT EXISTS idx_player_mappings_db_name ON player_mappings(db_name);
