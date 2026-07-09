# backend/database.py
import os
import psycopg
from psycopg.rows import dict_row
import bcrypt

DATABASE_URL = os.environ.get(
    'DATABASE_URL',
    'postgresql://neondb_owner:npg_UI4DeQ2PMZYf@ep-billowing-dream-atdbfg0b-pooler.c-9.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require'
)


class _Row(dict):
    """Dict that also supports integer indexing like sqlite3.Row / RealDictRow."""

    def __getitem__(self, key):
        if isinstance(key, (int, slice)):
            return list(self.values())[key]
        return super().__getitem__(key)


def _row_factory(cursor):
    if cursor.description is None:
        return lambda record: None
    columns = tuple(d.name for d in cursor.description)
    def _make_row(record):
        return _Row(zip(columns, record))
    return _make_row


class _Connection:
    """Wraps a psycopg connection to mimic SQLite's conn.execute() shortcut."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=None):
        if params is None:
            params = ()
        c = self._conn.cursor(row_factory=_row_factory)
        c.execute(sql, params)
        return c

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


def get_db():
    conn = psycopg.connect(DATABASE_URL)
    conn.autocommit = False
    return _Connection(conn)


def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id             SERIAL PRIMARY KEY,
            student_number TEXT UNIQUE,
            name           TEXT NOT NULL,
            email          TEXT NOT NULL UNIQUE,
            password       TEXT NOT NULL,
            role           TEXT NOT NULL DEFAULT 'student',
            is_active      INTEGER NOT NULL DEFAULT 1,
            created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS student_profiles (
            id                 SERIAL PRIMARY KEY,
            user_id            INTEGER NOT NULL UNIQUE,
            program            TEXT,
            year_of_study      INTEGER,
            defense_status     TEXT NOT NULL DEFAULT 'not_submitted',
            defense_passed_at  TIMESTAMP,
            defense_passed_by  INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS clearance_items (
            id          SERIAL PRIMARY KEY,
            title       TEXT NOT NULL,
            description TEXT,
            office_role TEXT NOT NULL,
            sort_order  INTEGER DEFAULT 0,
            is_active   INTEGER NOT NULL DEFAULT 1
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS clearance_requests (
            id                SERIAL PRIMARY KEY,
            student_id        INTEGER NOT NULL,
            clearance_item_id INTEGER NOT NULL,
            status            TEXT NOT NULL DEFAULT 'pending',
            reviewed_by       INTEGER,
            reviewed_at       TIMESTAMP,
            remarks           TEXT,
            created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (student_id, clearance_item_id),
            FOREIGN KEY (student_id)        REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (clearance_item_id) REFERENCES clearance_items(id) ON DELETE CASCADE
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id         SERIAL PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            title      TEXT NOT NULL,
            message    TEXT NOT NULL,
            is_read    INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS graduation_settings (
            id              SERIAL PRIMARY KEY,
            graduation_date TEXT NOT NULL,
            academic_year   TEXT,
            updated_by      INTEGER,
            updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS document_types (
            id              SERIAL PRIMARY KEY,
            name            TEXT NOT NULL,
            description     TEXT,
            reviewing_role  TEXT NOT NULL,
            is_required     INTEGER NOT NULL DEFAULT 1,
            sort_order      INTEGER DEFAULT 0
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS student_documents (
            id                SERIAL PRIMARY KEY,
            student_id        INTEGER NOT NULL,
            document_type_id  INTEGER NOT NULL,
            filename          TEXT NOT NULL,
            original_name     TEXT NOT NULL,
            file_size         INTEGER,
            mime_type         TEXT,
            status            TEXT NOT NULL DEFAULT 'pending',
            reviewed_by       INTEGER,
            reviewed_at       TIMESTAMP,
            rejection_reason  TEXT,
            uploaded_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id)       REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (document_type_id) REFERENCES document_types(id),
            FOREIGN KEY (reviewed_by)      REFERENCES users(id)
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS document_submissions (
            id           SERIAL PRIMARY KEY,
            student_id   INTEGER NOT NULL UNIQUE,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status       TEXT NOT NULL DEFAULT 'submitted',
            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    existing = db.execute("SELECT COUNT(*) FROM clearance_items").fetchone()[0]
    if existing == 0:
        for item in [
            ('Library Clearance',    'Return all borrowed books and clear any library fines.',           'library',    1),
            ('Finance Clearance',    'Clear all outstanding tuition fees and financial obligations.',    'finance',    2),
            ('Department Clearance', 'Submit all required academic work and departmental requirements.', 'department', 3),
            ('Academics Clearance',   'Confirm all academic records are complete and up to date.',        'academics',   4),
        ]:
            db.execute(
                "INSERT INTO clearance_items (title, description, office_role, sort_order) VALUES (%s,%s,%s,%s)",
                item
            )

    existing_docs = db.execute("SELECT COUNT(*) FROM document_types").fetchone()[0]
    if existing_docs == 0:
        for doc in [
            ('Grade 12 Certificate',              'Original Grade 12 certificate showing at least 5 O-Level credits or better.',         'academics',   1, 1),
            ('Academic Transcript',               'Official university academic transcript showing all completed courses and grades.',     'academics',   1, 2),
            ('Proof of Graduation Fee Payment',   'Bank receipt or payment confirmation for the graduation fee.',                         'finance',    1, 3),
            ('Financial Clearance Statement',     'Official statement confirming all tuition fees and financial obligations are settled.', 'finance',    1, 4),
            ('Library Clearance Certificate',     'Certificate from the library confirming all books are returned and fines are cleared.', 'library',    1, 5),
            ('Viva Voce / Dissertation Defence Record', 'Official record of your dissertation defence examination outcome.',              'supervisor', 1, 6),
            ('NRC (National Registration Card)',  'A clear copy of your valid National Registration Card.',                               'academics',   1, 7),
        ]:
            db.execute(
                "INSERT INTO document_types (name, description, reviewing_role, is_required, sort_order) VALUES (%s,%s,%s,%s,%s)",
                doc
            )

    admin = db.execute("SELECT id FROM users WHERE email = 'admin@cavendish.co.zm'").fetchone()
    if not admin:
        hashed = bcrypt.hashpw(b'Admin@1234', bcrypt.gensalt()).decode()
        db.execute(
            "INSERT INTO users (name, email, password, role) VALUES (%s,%s,%s,%s)",
            ('System Admin', 'admin@cavendish.co.zm', hashed, 'admin')
        )

    grad = db.execute("SELECT id FROM graduation_settings").fetchone()
    if not grad:
        db.execute(
            "INSERT INTO graduation_settings (graduation_date, academic_year) VALUES (%s,%s)",
            ('2026-09-30', '2025/2026')
        )

    db.commit()
    db.close()
    print("Database ready.")
