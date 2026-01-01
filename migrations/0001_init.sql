-- Migration number: 0001
CREATE TABLE IF NOT EXISTS product_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_value TEXT NOT NULL,
    semver_range TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);