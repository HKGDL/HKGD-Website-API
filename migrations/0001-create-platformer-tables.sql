-- Migration to create platformer_levels and move records from levels to platformer_records

CREATE TABLE platformer_levels (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    difficulty INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

INSERT INTO platformer_levels (name, difficulty) 
SELECT name, difficulty FROM levels;

CREATE TABLE platformer_records (
    id SERIAL PRIMARY KEY,
    level_id INT NOT NULL,
    user_id INT NOT NULL,
    score INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (level_id) REFERENCES platformer_levels(id)
);

INSERT INTO platformer_records (level_id, user_id, score) 
SELECT pl.id, lr.user_id, lr.score 
FROM levels AS lr 
JOIN platformer_levels AS pl ON lr.name = pl.name; 

-- Drop levels table if needed
-- DROP TABLE IF EXISTS levels;  
