-- Student Marketplace — database schema (SQLite)
-- Main process: register -> post listing -> search -> message seller -> mark as sold

PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS reviews;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS favourites;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS listings;
DROP TABLE IF EXISTS categories;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id    TEXT    NOT NULL UNIQUE,          -- e.g. 24B031936
    full_name     TEXT    NOT NULL,
    email         TEXT    NOT NULL UNIQUE CHECK (email LIKE '%@%'),
    password_hash TEXT    NOT NULL,                 -- never store plain passwords
    phone         TEXT,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE categories (
    category_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE
);

CREATE TABLE listings (
    listing_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    seller_id   INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    category_id INTEGER NOT NULL REFERENCES categories(category_id),
    title       TEXT    NOT NULL,
    description TEXT,
    price       INTEGER NOT NULL CHECK (price >= 0),          -- tenge
    condition   TEXT    NOT NULL CHECK (condition IN ('new', 'used')),
    status      TEXT    NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'sold', 'hidden')),
    image_path  TEXT,                                         -- photo, e.g. uploads/ab12.jpg (file lives in static/)
    course      TEXT,                                         -- course code the item is for, e.g. MATH101 (campus filter)
    pickup_place TEXT,                                        -- where on campus the deal happens, e.g. Library
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE messages (
    message_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id  INTEGER NOT NULL REFERENCES listings(listing_id) ON DELETE CASCADE,
    sender_id   INTEGER NOT NULL REFERENCES users(user_id),
    receiver_id INTEGER NOT NULL REFERENCES users(user_id),
    text        TEXT    NOT NULL,
    sent_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    is_read     INTEGER NOT NULL DEFAULT 0 CHECK (is_read IN (0, 1)),   -- 0 = receiver has not opened it yet
    CHECK (sender_id <> receiver_id)
);

CREATE TABLE favourites (
    favourite_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(user_id)       ON DELETE CASCADE,
    listing_id   INTEGER NOT NULL REFERENCES listings(listing_id) ON DELETE CASCADE,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (user_id, listing_id)      -- the same listing cannot be saved twice
);

-- Seller reviews: a buyer rates the seller after a sale (rating 1-5 + written feedback)
CREATE TABLE reviews (
    review_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id  INTEGER NOT NULL REFERENCES listings(listing_id) ON DELETE CASCADE,
    seller_id   INTEGER NOT NULL REFERENCES users(user_id)       ON DELETE CASCADE,
    reviewer_id INTEGER NOT NULL REFERENCES users(user_id)       ON DELETE CASCADE,
    rating      INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment     TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (listing_id, reviewer_id),          -- one review per buyer per deal
    CHECK (seller_id <> reviewer_id)           -- nobody reviews themselves
);

-- Failed logins, used to lock an email after too many wrong passwords (brute-force protection)
CREATE TABLE login_attempts (
    attempt_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    email        TEXT    NOT NULL,
    ip           TEXT,
    attempted_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Indexes for the most common searches
CREATE INDEX idx_listings_category_price ON listings(category_id, price);
CREATE INDEX idx_listings_status         ON listings(status);
CREATE INDEX idx_messages_listing        ON messages(listing_id);
CREATE INDEX idx_favourites_user          ON favourites(user_id);
CREATE INDEX idx_login_attempts_email    ON login_attempts(email, attempted_at);
CREATE INDEX idx_messages_sender         ON messages(sender_id, sent_at);
CREATE INDEX idx_messages_unread         ON messages(receiver_id, is_read);
CREATE INDEX idx_reviews_seller           ON reviews(seller_id);
CREATE INDEX idx_listings_course         ON listings(course);
