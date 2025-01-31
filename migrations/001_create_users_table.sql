-- Create the users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, -- Unique ID for each user
    username TEXT NOT NULL UNIQUE,       -- Username, must be unique
    password_hash TEXT NOT NULL         -- Hashed password for security
);

-- Create an index on the username and email columns for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
