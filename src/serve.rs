use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::extract::{self, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Map, Value};
use tracing::info;

use crate::app::App;
use crate::cve::{self, CVES};
use crate::db::CANDIDATE_ENTRY;

const DASHBOARD: &str = include_str!("dashboard.html");

/// Data files the dashboard loads from `api/<name>.json`.
const DATA_FILES: &[&str] = &["meta", "versions", "detection", "installers", "cves"];

fn queries() -> HashMap<&'static str, String> {
    let latest_entries = format!("JOIN manifest_entries e ON e.sha256 = f.sha256 AND {CANDIDATE_ENTRY}");
    HashMap::from([
        ("meta", "SELECT key, value FROM meta".to_string()),
        (
            "versions",
            format!(
                "SELECT f.nsis_version, COUNT(DISTINCT f.sha256) AS files,
                     COUNT(DISTINCT e.package_id) AS packages
                 FROM files f {latest_entries}
                 WHERE f.detected_type = 'nsis' GROUP BY 1"
            ),
        ),
        (
            "detection",
            format!(
                "SELECT e.installer_type AS winget_type,
                     CASE WHEN f.probe_state = 'done' THEN f.detected_type ELSE f.probe_state END AS result,
                     COUNT(DISTINCT f.sha256) AS files
                 FROM files f {latest_entries} GROUP BY 1, 2"
            ),
        ),
        (
            "installers",
            format!(
                "SELECT e.package_id AS package, e.version, group_concat(DISTINCT e.architecture) AS architectures,
                     e.installer_type AS winget_type, f.probe_state AS state, f.detected_type AS detected,
                     f.nsis_version, f.description, f.wrapper, f.http_status, f.last_error AS error, f.file_size,
                     f.head_size, f.url, f.sha256
                 FROM files f {latest_entries}
                 GROUP BY e.package_id, f.sha256 ORDER BY e.package_id"
            ),
        ),
    ])
}

struct Dashboard {
    db_path: PathBuf,
    queries: HashMap<&'static str, String>,
}

impl Dashboard {
    fn data(&self, name: &str) -> Result<Option<Value>> {
        if name == "cves" {
            let rules = CVES.iter().map(|c| serde_json::json!({ "id": c.id, "range": c.range() })).collect();
            return Ok(Some(Value::Array(rules)));
        }
        let Some(sql) = self.queries.get(name) else { return Ok(None) };
        let conn = Connection::open_with_flags(&self.db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut stmt = conn.prepare(sql)?;
        let names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let rows = stmt
            .query_map([], |row| {
                let mut object = Map::new();
                for (i, name) in names.iter().enumerate() {
                    let value = match row.get_ref(i)? {
                        ValueRef::Null | ValueRef::Blob(_) => Value::Null,
                        ValueRef::Integer(n) => n.into(),
                        ValueRef::Real(n) => n.into(),
                        ValueRef::Text(t) => String::from_utf8_lossy(t).into(),
                    };
                    object.insert(name.clone(), value);
                }
                if let Some(version) = object.get("nsis_version") {
                    let cves = version.as_str().and_then(cve::affected);
                    object.insert("cves".to_string(), serde_json::to_value(cves).unwrap_or_default());
                }
                Ok(Value::Object(object))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(Value::Array(rows)))
    }
}

async fn index() -> Html<&'static str> {
    Html(DASHBOARD)
}

async fn api(State(dashboard): State<Arc<Dashboard>>, extract::Path(file): extract::Path<String>) -> Response {
    let Some(name) = file.strip_suffix(".json").map(str::to_string) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let result = tokio::task::spawn_blocking(move || dashboard.data(&name)).await;
    match result {
        Ok(Ok(Some(rows))) => ([(header::CACHE_CONTROL, "no-store")], Json(rows)).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

impl App {
    fn dashboard(&self) -> Result<Dashboard> {
        let db_path = self.data_dir.join("winget-stats.db");
        if !db_path.exists() {
            bail!("no database at {}, run the index command first", db_path.display());
        }
        Ok(Dashboard { db_path, queries: queries() })
    }

    pub fn serve(&self, listen: &str) -> Result<()> {
        let dashboard = Arc::new(self.dashboard()?);
        let router = Router::new().route("/", get(index)).route("/api/{file}", get(api)).with_state(dashboard);

        self.runtime.block_on(async {
            let listener =
                tokio::net::TcpListener::bind(listen).await.with_context(|| format!("cannot listen on {listen}"))?;
            info!("Dashboard at http://{}", listener.local_addr()?);
            axum::serve(listener, router).await?;
            Ok(())
        })
    }

    /// Writes the dashboard and its data as static files for any web host.
    pub fn export(&self, output: &Path) -> Result<()> {
        let dashboard = self.dashboard()?;
        let api_dir = output.join("api");
        std::fs::create_dir_all(&api_dir).with_context(|| format!("cannot create {}", api_dir.display()))?;
        std::fs::write(output.join("index.html"), DASHBOARD)?;

        let mut total = DASHBOARD.len();
        for name in DATA_FILES {
            let data = dashboard.data(name)?.with_context(|| format!("no query for {name}"))?;
            let bytes = serde_json::to_vec(&data)?;
            std::fs::write(api_dir.join(format!("{name}.json")), &bytes)?;
            total += bytes.len();
        }
        info!("Exported dashboard to {} ({:.1} MB)", output.display(), total as f64 / 1e6);
        Ok(())
    }
}
