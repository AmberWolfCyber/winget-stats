use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use reqwest::header::{CONTENT_RANGE, CONTENT_TYPE, RANGE};
use reqwest::{Client, Response, StatusCode};
use rusqlite::{Connection, params};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{debug, info};

use crate::app::App;
use crate::db::PROBE_SCOPE;
use crate::pe::{self, Layout};

/// Size of the first range request. It covers the stub of most NSIS installers.
const FIRST_RANGE: usize = 512 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const RETRIES: u32 = 2;

pub struct ProbeOptions {
    pub concurrency: usize,
    pub per_host: usize,
    pub max_attempts: u32,
    pub limit: Option<usize>,
}

#[derive(Debug)]
struct ProbeResult {
    sha256: String,
    state: &'static str,
    http_status: Option<u16>,
    error: Option<String>,
    file_size: Option<i64>,
    head_size: Option<i64>,
    inspection: pe::Inspection,
}

#[derive(Debug)]
struct FetchError {
    status: Option<u16>,
    message: String,
    retryable: bool,
}

impl From<reqwest::Error> for FetchError {
    fn from(e: reqwest::Error) -> Self {
        let mut message = e.to_string();
        let mut source = std::error::Error::source(&e);
        while let Some(cause) = source {
            message.push_str(&format!(": {cause}"));
            source = cause.source();
        }
        Self { status: e.status().map(|s| s.as_u16()), message, retryable: true }
    }
}

struct Head {
    bytes: Vec<u8>,
    layout: Layout,
    complete: bool,
    status: u16,
    file_size: Option<u64>,
    content_type: Option<String>,
}

/// Reads a response body and continues with a new range request when the first range ends too early.
struct BodyReader<'a> {
    client: &'a Client,
    url: &'a str,
    response: Response,
    partial: bool,
    file_size: Option<u64>,
    bytes: Vec<u8>,
}

impl BodyReader<'_> {
    async fn fill(&mut self, wanted: usize) -> Result<(), FetchError> {
        while self.bytes.len() < wanted {
            if let Some(chunk) = self.response.chunk().await? {
                self.bytes.extend_from_slice(&chunk);
                continue;
            }
            let more = self.file_size.is_some_and(|size| (self.bytes.len() as u64) < size);
            if !self.partial || !more {
                break;
            }
            let start = self.bytes.len();
            let end = wanted.max(start + FIRST_RANGE) - 1;
            let response = self.client.get(self.url).header(RANGE, format!("bytes={start}-{end}")).send().await?;
            if response.status() != StatusCode::PARTIAL_CONTENT {
                return Err(FetchError {
                    status: Some(response.status().as_u16()),
                    message: format!("follow-up range request returned {}", response.status()),
                    retryable: true,
                });
            }
            self.response = response;
        }
        Ok(())
    }
}

struct Prober {
    client: Client,
    heads_dir: PathBuf,
}

impl Prober {
    async fn probe(&self, sha256: String, url: String) -> ProbeResult {
        let mut result = ProbeResult {
            sha256,
            state: "failed",
            http_status: None,
            error: None,
            file_size: None,
            head_size: None,
            inspection: pe::Inspection::default(),
        };
        for attempt in 0..=RETRIES {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(2u64.pow(attempt))).await;
            }
            let error = match tokio::time::timeout(REQUEST_TIMEOUT, self.fetch_head(&url)).await {
                Ok(Ok(head)) => return self.finish(result, head).await,
                Ok(Err(e)) => e,
                Err(_) => FetchError { status: None, message: "request timed out".into(), retryable: true },
            };
            debug!("{url}: attempt {} failed: {}", attempt + 1, error.message);
            result.http_status = error.status;
            result.error = Some(error.message);
            if matches!(error.status, Some(404 | 410)) {
                result.state = "gone";
            }
            if !error.retryable {
                break;
            }
        }
        result
    }

    async fn fetch_head(&self, url: &str) -> Result<Head, FetchError> {
        let response = self.client.get(url).header(RANGE, format!("bytes=0-{}", FIRST_RANGE - 1)).send().await?;
        let status = response.status();
        if !matches!(status, StatusCode::OK | StatusCode::PARTIAL_CONTENT) {
            let code = status.as_u16();
            return Err(FetchError {
                status: Some(code),
                message: format!("HTTP {status}"),
                retryable: code == 429 || status.is_server_error(),
            });
        }

        let partial = status == StatusCode::PARTIAL_CONTENT;
        let file_size = if partial { content_range_total(&response) } else { response.content_length() };
        let content_type = response.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_string);
        let mut reader = BodyReader { client: &self.client, url, response, partial, file_size, bytes: Vec::new() };

        let layout = loop {
            match pe::layout(&reader.bytes) {
                Layout::NeedMore(n) if n <= pe::MAX_HEAD_BYTES && reader.bytes.len() < n => {
                    reader.fill(n).await?;
                    if reader.bytes.len() < n {
                        break Layout::NotPe;
                    }
                }
                Layout::NeedMore(_) => break Layout::NotPe,
                other => break other,
            }
        };
        let mut complete = true;
        if let Layout::SectionsEnd(end) = layout {
            let wanted = (end + pe::OVERLAY_BYTES).min(pe::MAX_HEAD_BYTES);
            complete = wanted == end + pe::OVERLAY_BYTES;
            reader.fill(wanted).await?;
            reader.bytes.truncate(wanted);
        }
        Ok(Head { bytes: reader.bytes, layout, complete, status: status.as_u16(), file_size, content_type })
    }

    async fn finish(&self, mut result: ProbeResult, head: Head) -> ProbeResult {
        result.state = "done";
        result.http_status = Some(head.status);
        result.file_size = head.file_size.map(|s| s as i64);
        result.head_size = Some(head.bytes.len() as i64);
        result.error = None;
        result.inspection = match head.layout {
            Layout::SectionsEnd(_) => {
                let mut inspection = pe::inspect(&head.bytes);
                if !head.complete && inspection.detected_type == "pe" {
                    inspection.detected_type = "pe_partial";
                }
                inspection
            }
            _ => {
                result.error = head.content_type.map(|t| format!("content type {t}"));
                pe::Inspection { detected_type: "not_pe", ..Default::default() }
            }
        };

        let dir = self.heads_dir.join(&result.sha256[..2]);
        let path = dir.join(format!("{}.head", result.sha256));
        let written = async {
            tokio::fs::create_dir_all(&dir).await?;
            tokio::fs::write(&path, &head.bytes).await
        };
        if let Err(e) = written.await {
            result.state = "failed";
            result.error = Some(format!("cannot write {}: {e}", path.display()));
        }
        result
    }
}

fn content_range_total(response: &Response) -> Option<u64> {
    let value = response.headers().get(CONTENT_RANGE)?.to_str().ok()?;
    value.rsplit('/').next()?.trim().parse().ok()
}

fn url_host(url: &str) -> String {
    reqwest::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_lowercase)).unwrap_or_default()
}

impl App {
    pub fn probe(&mut self, options: ProbeOptions) -> Result<()> {
        let jobs = self.probe_jobs(options.max_attempts, options.limit)?;
        if jobs.is_empty() {
            info!("Nothing to probe");
            return Ok(());
        }
        info!("Probing {} files with {} connections", jobs.len(), options.concurrency);

        let prober = Arc::new(Prober { client: self.client.clone(), heads_dir: self.data_dir.join("heads") });
        let total = jobs.len();
        let conn = &mut self.conn;
        let runtime = &self.runtime;
        let (sender, receiver) = mpsc::channel();

        std::thread::scope(|scope| {
            let writer = scope.spawn(move || write_results(conn, receiver, total));
            runtime.block_on(async {
                let global = Arc::new(Semaphore::new(options.concurrency));
                let mut hosts: HashMap<String, Arc<Semaphore>> = HashMap::new();
                let mut tasks = JoinSet::new();
                for (sha256, url) in jobs {
                    let host =
                        hosts.entry(url_host(&url)).or_insert_with(|| Arc::new(Semaphore::new(options.per_host)));
                    let (host, global, prober, sender) = (host.clone(), global.clone(), prober.clone(), sender.clone());
                    tasks.spawn(async move {
                        // Take the host permit first so tasks that wait for a busy host do not hold a global slot
                        let _host = host.acquire_owned().await;
                        let _global = global.acquire_owned().await;
                        let result = prober.probe(sha256, url).await;
                        let _ = sender.send(result);
                    });
                }
                drop(sender);
                while tasks.join_next().await.is_some() {}
            });
            writer.join().expect("result writer panicked")
        })
    }

    fn probe_jobs(&self, max_attempts: u32, limit: Option<usize>) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT sha256, url FROM files f
             WHERE (probe_state = 'pending' OR (probe_state = 'failed' AND attempts < ?1)) AND {PROBE_SCOPE}
             ORDER BY random() LIMIT ?2"
        ))?;
        let limit = limit.map_or(-1, |l| l as i64);
        let rows = stmt.query_map(params![max_attempts, limit], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

fn write_results(conn: &mut Connection, receiver: mpsc::Receiver<ProbeResult>, total: usize) -> Result<()> {
    let mut update = conn.prepare(
        "UPDATE files SET probe_state = ?2, attempts = attempts + 1, http_status = ?3, last_error = ?4,
             file_size = ?5, head_size = ?6, detected_type = ?7, description = ?8, nsis_version = ?9,
             nsis_signature = ?10, probed_at = ?11
         WHERE sha256 = ?1",
    )?;
    let mut counts: HashMap<&'static str, usize> = HashMap::new();
    let mut done = 0usize;
    for r in receiver {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let detected_type = (!r.inspection.detected_type.is_empty()).then_some(r.inspection.detected_type);
        update.execute(params![
            r.sha256,
            r.state,
            r.http_status,
            r.error,
            r.file_size,
            r.head_size,
            detected_type,
            r.inspection.description,
            r.inspection.nsis_version,
            r.inspection.nsis_signature,
            now,
        ])?;
        *counts.entry(detected_type.unwrap_or(r.state)).or_default() += 1;
        done += 1;
        if done.is_multiple_of(250) || done == total {
            let mut summary: Vec<_> = counts.iter().collect();
            summary.sort_by(|a, b| b.1.cmp(a.1));
            let summary: Vec<String> = summary.iter().map(|(k, v)| format!("{k} {v}")).collect();
            info!("Probed {done}/{total}: {}", summary.join(", "));
        }
    }
    Ok(())
}
