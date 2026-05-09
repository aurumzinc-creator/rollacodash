import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'velodash.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    # Users (admin & athletes)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT UNIQUE NOT NULL,
        password    TEXT NOT NULL,
        role        TEXT NOT NULL DEFAULT 'athlete',  -- 'admin' | 'athlete'
        created_at  TEXT DEFAULT (datetime('now'))
    )''')

    # Athlete profiles
    c.execute('''CREATE TABLE IF NOT EXISTS athletes (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id         INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        full_name       TEXT NOT NULL,
        birth_date      TEXT,
        gender          TEXT,          -- 'L' | 'P'
        weight_kg       REAL,
        height_cm       REAL,
        category        TEXT,          -- Challenge_5_6 | Challenge_7_8 | Challenge_9_10 | Challenge_11_12 | Challenge_13_14 | Youth | Junior | U23 | Elite
        experience_years INTEGER DEFAULT 0,
        health_notes    TEXT,
        strava_connected INTEGER DEFAULT 0,
        resting_hr      INTEGER,       -- baseline resting heart rate
        max_hr          INTEGER,       -- max heart rate (measured or formula)
        photo_url       TEXT,
        created_at      TEXT DEFAULT (datetime('now'))
    )''')

    # Training sessions
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        athlete_id      INTEGER REFERENCES athletes(id) ON DELETE CASCADE,
        session_date    TEXT NOT NULL,
        session_type    TEXT NOT NULL,  -- team_rantai | ITT | interval | hill_repeat | rolling | endurance | recovery
        route_type      TEXT,           -- flat | hill | rolling | mixed
        duration_min    INTEGER,
        distance_km     REAL,
        elevation_m     REAL,
        avg_speed_kmh   REAL,
        max_speed_kmh   REAL,
        avg_hr          INTEGER,
        max_hr          INTEGER,
        avg_cadence     INTEGER,
        max_cadence     INTEGER,
        rpe             INTEGER,        -- 1-10
        calories        INTEGER,
        suffer_score    INTEGER,
        notes           TEXT,
        data_source     TEXT DEFAULT 'manual',  -- manual | strava | fit_file | gpx
        strava_id       TEXT,
        created_at      TEXT DEFAULT (datetime('now'))
    )''')

    # HR Zone distributions per session
    c.execute('''CREATE TABLE IF NOT EXISTS hr_zones (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id  INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
        zone1_min   INTEGER DEFAULT 0,  -- Recovery (<60% max)
        zone2_min   INTEGER DEFAULT 0,  -- Endurance (60-70%)
        zone3_min   INTEGER DEFAULT 0,  -- Tempo (70-80%)
        zone4_min   INTEGER DEFAULT 0,  -- Threshold (80-90%)
        zone5_min   INTEGER DEFAULT 0   -- VO2Max (>90%)
    )''')

    # Weekly goals set by admin
    c.execute('''CREATE TABLE IF NOT EXISTS weekly_goals (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        athlete_id      INTEGER REFERENCES athletes(id) ON DELETE CASCADE,
        week_start      TEXT NOT NULL,  -- Monday ISO date
        target_sessions INTEGER DEFAULT 4,
        target_km       REAL,
        target_duration_min INTEGER,
        target_types    TEXT,           -- JSON array of session types
        notes           TEXT,
        created_by      INTEGER REFERENCES users(id)
    )''')

    # Coach notes / evaluations per athlete
    c.execute('''CREATE TABLE IF NOT EXISTS evaluations (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        athlete_id  INTEGER REFERENCES athletes(id) ON DELETE CASCADE,
        eval_date   TEXT NOT NULL,
        period      TEXT,       -- weekly | monthly
        coach_notes TEXT,
        ai_report   TEXT,       -- AI-generated report JSON
        created_by  INTEGER REFERENCES users(id),
        created_at  TEXT DEFAULT (datetime('now'))
    )''')

    # Seed admin account
    import bcrypt
    admin_pw = bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode()
    c.execute('''INSERT OR IGNORE INTO users (username, password, role)
                 VALUES ('admin', ?, 'admin')''', (admin_pw,))

    conn.commit()
    conn.close()
    print("✅ Database initialized:", DB_PATH)

if __name__ == '__main__':
    init_db()
