CREATE TABLE IF NOT EXISTS kick (
    id INTEGER PRIMARY KEY AUTOINCREMENT, -- Unique ID for each kick
    user_name VARCHAR(255) NOT NULL -- ID of the user who made the kick
);

-- -- Create an index on the user_name column for faster lookups
CREATE INDEX IF NOT EXISTS idx_kick_user_name ON kick (user_name);
