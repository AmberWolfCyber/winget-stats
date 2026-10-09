use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};
use tracing::info;

use crate::cve::{self, CVES};
use crate::db::{self, PROBE_SCOPE, STATS_SCOPE};

const USER_AGENT: &str = concat!("winget-stats/", env!("CARGO_PKG_VERSION"));

pub struct App {
    pub data_dir: PathBuf,
    pub runtime: tokio::runtime::Runtime,
    pub client: reqwest::Client,
    pub conn: Connection,
}

impl App {
    pub fn new(data_dir: PathBuf, proxy: Option<&str>) -> Result<Self> {
        std::fs::create_dir_all(&data_dir).with_context(|| format!("cannot create {}", data_dir.display()))?;

        let mut builder = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(Duration::from_secs(20))
            .read_timeout(Duration::from_secs(60));
        if let Some(proxy) = proxy {
            let proxy_url = format!("http://{proxy}");
            builder = builder
                .proxy(reqwest::Proxy::all(&proxy_url).with_context(|| format!("invalid proxy {proxy_url}"))?)
                .danger_accept_invalid_certs(true);
        }

        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        let conn = db::open(&data_dir.join("winget-stats.db"))?;
        Ok(Self { data_dir, runtime, client: builder.build()?, conn })
    }

    fn log_rows(&self, title: &str, sql: &str) -> Result<()> {
        info!("{title}");
        let mut stmt = self.conn.prepare(sql)?;
        let columns = stmt.column_count();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let label: String = row.get::<_, Option<String>>(0)?.unwrap_or_else(|| "-".to_string());
            let values: Vec<String> =
                (1..columns).map(|i| row.get::<_, i64>(i).map(|v| format!("{v:>8}"))).collect::<Result<_, _>>()?;
            info!("  {label:<28} {}", values.join(" "));
        }
        Ok(())
    }

    pub fn status(&self) -> Result<()> {
        let commit: Option<String> =
            self.conn.query_row("SELECT value FROM meta WHERE key = 'source_commit'", [], |r| r.get(0)).optional()?;
        info!("Source commit: {}", commit.as_deref().unwrap_or("-"));

        let (packages, versions): (i64, i64) = self.conn.query_row(
            "SELECT COUNT(DISTINCT package_id), COUNT(DISTINCT package_id || '|' || version) FROM manifest_entries",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        info!("Packages: {packages}, versions: {versions}");

        self.log_rows(
            "Latest versions by installer type (entries, unique files):",
            "SELECT installer_type, COUNT(*), COUNT(DISTINCT sha256) FROM manifest_entries
             WHERE is_latest GROUP BY 1 ORDER BY 3 DESC",
        )?;
        self.log_rows(
            "Files to probe by state:",
            &format!("SELECT probe_state, COUNT(*) FROM files f WHERE {PROBE_SCOPE} GROUP BY 1 ORDER BY 2 DESC"),
        )?;
        self.log_rows(
            "Probed files by detected type:",
            &format!(
                "SELECT detected_type, COUNT(*) FROM files f WHERE probe_state = 'done' AND {STATS_SCOPE}
                 GROUP BY 1 ORDER BY 2 DESC"
            ),
        )?;
        self.log_rows(
            "Unpack by wrapper and state (files, MB fetched):",
            &format!(
                "SELECT COALESCE(wrapper, 'none') || ' ' || unpack_state, COUNT(*), COALESCE(SUM(unpack_bytes), 0) / 1000000
                 FROM files f WHERE unpack_state IS NOT NULL AND {STATS_SCOPE} GROUP BY 1 ORDER BY 2 DESC"
            ),
        )?;
        self.log_rows(
            "Top NSIS versions (files, packages):",
            &format!(
                "SELECT f.nsis_version, COUNT(DISTINCT f.sha256), COUNT(DISTINCT e.package_id)
                 FROM files f JOIN manifest_entries e ON e.sha256 = f.sha256 AND e.is_latest
                 WHERE f.detected_type = 'nsis' AND {STATS_SCOPE}
                 GROUP BY 1 ORDER BY 3 DESC LIMIT 15"
            ),
        )?;
        self.log_cves()
    }

    fn log_cves(&self) -> Result<()> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT e.package_id, f.nsis_version FROM files f
             JOIN manifest_entries e ON e.sha256 = f.sha256 AND e.is_latest AND NOT e.locale_variant
             WHERE f.detected_type = 'nsis'",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))?;
        let mut affected: HashMap<&str, HashSet<String>> = HashMap::new();
        let mut unknown = HashSet::new();
        let mut packages = HashSet::new();
        for row in rows {
            let (package, version) = row?;
            match version.as_deref().and_then(cve::affected) {
                Some(ids) => ids.into_iter().for_each(|id| {
                    affected.entry(id).or_default().insert(package.clone());
                }),
                None => {
                    unknown.insert(package.clone());
                }
            }
            packages.insert(package);
        }

        info!("NSIS packages affected by known CVEs (of {}):", packages.len());
        for c in CVES {
            let count = affected.get(c.id).map_or(0, HashSet::len);
            info!("  {:<16} {:>8}  {}", c.id, count, c.range());
        }
        let any: HashSet<&String> = affected.values().flatten().collect();
        info!("  {:<16} {:>8}", "Any CVE", any.len());
        info!("  {:<16} {:>8}  development build or no version", "Unknown", unknown.len());
        Ok(())
    }
}
