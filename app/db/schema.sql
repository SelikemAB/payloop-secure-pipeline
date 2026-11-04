CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT NOT NULL UNIQUE,
    pass_hash TEXT NOT NULL,
    role      TEXT NOT NULL DEFAULT 'customer'
);
CREATE TABLE IF NOT EXISTS wallets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id      INTEGER NOT NULL REFERENCES users(id),
    balance_minor INTEGER NOT NULL DEFAULT 0,
    currency      TEXT NOT NULL DEFAULT 'GHS'
);
CREATE TABLE IF NOT EXISTS transfers (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    from_wallet  INTEGER NOT NULL REFERENCES wallets(id),
    to_wallet    INTEGER NOT NULL,
    amount_minor INTEGER NOT NULL,
    idem_key     TEXT,
    note         TEXT,
    created_at   TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_transfers_idem ON transfers(from_wallet, idem_key) WHERE idem_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    k  TEXT NOT NULL,
    ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_login_attempts ON login_attempts(k, ts);
