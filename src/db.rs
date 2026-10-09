use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manifest_entries (
    package_id            TEXT NOT NULL,
    version               TEXT NOT NULL,
    is_latest             INTEGER NOT NULL,
    locale_variant        INTEGER NOT NULL,
    architecture          TEXT,
    scope                 TEXT,
    installer_locale      TEXT,
    installer_type        TEXT,
    nested_installer_type TEXT,
    nested_path           TEXT,
    url                   TEXT NOT NULL,
    sha256                TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_sha256 ON manifest_entries (sha256);
CREATE INDEX IF NOT EXISTS idx_entries_type ON manifest_entries (installer_type, is_latest);

CREATE TABLE IF NOT EXISTS files (
    sha256              TEXT PRIMARY KEY,
    url                 TEXT NOT NULL,
    probe_state         TEXT NOT NULL DEFAULT 'pending',
    attempts            INTEGER NOT NULL DEFAULT 0,
    http_status         INTEGER,
    last_error          TEXT,
    file_size           INTEGER,
    head_size           INTEGER,
    detected_type       TEXT,
    description         TEXT,
    nsis_version        TEXT,
    nsis_signature      INTEGER,
    probed_at           INTEGER,
    wrapper             TEXT,
    wrapper_description TEXT,
    nested_path         TEXT,
    unpack_state        TEXT,
    unpack_attempts     INTEGER NOT NULL DEFAULT 0,
    unpack_error        TEXT,
    unpack_bytes        INTEGER,
    unpack_requests     INTEGER
);
";

/// Latest-version installers that can hold NSIS, for a query that names the manifest entries table `e`.
pub const CANDIDATE_ENTRY: &str = "e.is_latest AND NOT e.locale_variant
    AND (e.installer_type IN ('nullsoft', 'exe')
        OR (e.installer_type = 'zip' AND e.nested_installer_type IN ('nullsoft', 'exe')))";

/// Files the probe phase fetches directly, for a query that names the files table `f`.
pub const PROBE_SCOPE: &str = "EXISTS (
    SELECT 1 FROM manifest_entries e
    WHERE e.sha256 = f.sha256 AND e.is_latest AND NOT e.locale_variant AND e.installer_type IN ('nullsoft', 'exe'))";

/// All files that can hold NSIS, including installers inside zip files, for a query that names the files table `f`.
pub const STATS_SCOPE: &str = "EXISTS (
    SELECT 1 FROM manifest_entries e
    WHERE e.sha256 = f.sha256 AND e.is_latest AND NOT e.locale_variant
        AND (e.installer_type IN ('nullsoft', 'exe')
            OR (e.installer_type = 'zip' AND e.nested_installer_type IN ('nullsoft', 'exe'))))";

pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("cannot open database {}", path.display()))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}
