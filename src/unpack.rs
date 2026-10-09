use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::header::{CONTENT_RANGE, RANGE};
use reqwest::{Client, StatusCode};
use rusqlite::{Connection, params};
use sevenz_rust2::{Archive, ArchiveEntry, BlockDecoder, Password};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{debug, info};

use crate::app::App;
use crate::db::PROBE_SCOPE;
use crate::pe::{self, Layout};

const SEVEN_ZIP_SIGNATURE: &[u8] = b"7z\xbc\xaf\x27\x1c";
/// 7-Zip archives are read in large blocks, because solid blocks are decoded from the start.
const SEVEN_ZIP_BLOCK_SIZE: u64 = 1024 * 1024;
/// Zip files need only the central directory and the start of one entry.
const ZIP_BLOCK_SIZE: u64 = 256 * 1024;
const CACHED_BLOCKS: usize = 64;
const BLOCK_RETRIES: u32 = 2;
/// Bytes past the outer stub to search for the 7-Zip signature.
const SIGNATURE_SEARCH_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_TARGET: &str = "setup.exe";

pub struct UnpackOptions {
    pub concurrency: usize,
    pub max_mb: u64,
    pub max_attempts: u32,
    pub limit: Option<usize>,
}

enum Kind {
    SevenZipSfx,
    Zip { path: Option<String> },
}

struct Job {
    sha256: String,
    url: String,
    file_size: Option<u64>,
    kind: Kind,
}

#[derive(Default)]
struct UnpackResult {
    sha256: String,
    wrapper: &'static str,
    file_size: Option<u64>,
    state: &'static str,
    error: Option<String>,
    nested_path: Option<String>,
    inspection: Option<pe::Inspection>,
    bytes: u64,
    requests: u32,
}

/// Read and seek over a remote file with HTTP range requests, starting at `base`.
struct RangeReader {
    client: Client,
    handle: Handle,
    url: String,
    base: u64,
    len: u64,
    pos: u64,
    block_size: u64,
    blocks: Vec<(u64, Vec<u8>)>,
    fetched: u64,
    requests: u32,
    limit: u64,
}

impl RangeReader {
    /// Reads the file size from the `Content-Range` header of a one-byte request.
    fn remote_size(&mut self) -> io::Result<u64> {
        self.requests += 1;
        let response = self
            .handle
            .block_on(self.client.get(&self.url).header(RANGE, "bytes=0-0").send())
            .map_err(io::Error::other)?;
        if response.status() != StatusCode::PARTIAL_CONTENT {
            return Err(io::Error::other(format!("range request returned {}", response.status())));
        }
        let total = response.headers().get(CONTENT_RANGE).and_then(|v| v.to_str().ok());
        total
            .and_then(|v| v.rsplit('/').next()?.trim().parse().ok())
            .ok_or_else(|| io::Error::other("no file size in Content-Range"))
    }

    fn block(&mut self, index: u64) -> io::Result<&[u8]> {
        if let Some(i) = self.blocks.iter().position(|(b, _)| *b == index) {
            return Ok(&self.blocks[i].1);
        }
        let start = self.base + index * self.block_size;
        let end = (start + self.block_size).min(self.base + self.len) - 1;
        if self.fetched + (end - start + 1) > self.limit {
            return Err(io::Error::other(format!("fetch limit of {} MB reached", self.limit / 1_000_000)));
        }

        let mut attempt = 0;
        let data = loop {
            self.requests += 1;
            match self.handle.block_on(fetch_range(&self.client, &self.url, start, end)) {
                Ok(data) => break data,
                Err(e) if attempt < BLOCK_RETRIES => {
                    debug!("{}: range {start}-{end} failed: {e}", self.url);
                    attempt += 1;
                    std::thread::sleep(Duration::from_secs(2u64.pow(attempt)));
                }
                Err(e) => return Err(e),
            }
        };
        self.fetched += data.len() as u64;
        if self.blocks.len() == CACHED_BLOCKS {
            self.blocks.remove(0);
        }
        self.blocks.push((index, data));
        Ok(&self.blocks.last().expect("block was just added").1)
    }
}

impl Read for RangeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let offset = (self.pos % self.block_size) as usize;
        let block = self.block(self.pos / self.block_size)?;
        let n = buf.len().min(block.len().saturating_sub(offset));
        buf[..n].copy_from_slice(&block[offset..offset + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for RangeReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let pos = match from {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.len as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if pos < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = pos as u64;
        Ok(self.pos)
    }
}

async fn fetch_range(client: &Client, url: &str, start: u64, end: u64) -> io::Result<Vec<u8>> {
    let response =
        client.get(url).header(RANGE, format!("bytes={start}-{end}")).send().await.map_err(io::Error::other)?;
    if response.status() != StatusCode::PARTIAL_CONTENT {
        return Err(io::Error::other(format!("range request returned {}", response.status())));
    }
    let bytes = response.bytes().await.map_err(io::Error::other)?;
    if bytes.len() as u64 != end - start + 1 {
        return Err(io::Error::other(format!("range returned {} bytes, expected {}", bytes.len(), end - start + 1)));
    }
    Ok(bytes.to_vec())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Reads the program that the SFX config runs, such as `RunProgram="setup.exe"`.
fn sfx_target(head: &[u8]) -> String {
    let start = find(head, b";!@Install@!UTF-8!");
    let config = start.map(|s| String::from_utf8_lossy(&head[s..(s + 4096).min(head.len())]).into_owned());
    config
        .and_then(|c| {
            c.lines().find_map(|line| {
                let value = line.strip_prefix("RunProgram=").or_else(|| line.strip_prefix("ExecuteFile="))?;
                let value = value.trim().trim_matches('"').trim_start_matches("hidcon:");
                let program = value.split_whitespace().next()?.trim_matches('"');
                Some(program.rsplit(['\\', '/']).next()?.to_string())
            })
        })
        .filter(|p| p.to_lowercase().ends_with(".exe"))
        .unwrap_or_else(|| DEFAULT_TARGET.to_string())
}

fn is_target(entry: &ArchiveEntry, target: &str) -> bool {
    !entry.is_directory && entry.name().eq_ignore_ascii_case(target)
}

struct Unpacker {
    client: Client,
    handle: Handle,
    heads_dir: PathBuf,
    limit: u64,
}

impl Unpacker {
    fn unpack(&self, job: Job) -> UnpackResult {
        let wrapper = match job.kind {
            Kind::SevenZipSfx => "7z_sfx",
            Kind::Zip { .. } => "zip",
        };
        let mut result = UnpackResult { sha256: job.sha256.clone(), wrapper, state: "failed", ..Default::default() };
        let mut reader = RangeReader {
            client: self.client.clone(),
            handle: self.handle.clone(),
            url: job.url.clone(),
            base: 0,
            len: job.file_size.unwrap_or(0),
            pos: 0,
            block_size: if wrapper == "zip" { ZIP_BLOCK_SIZE } else { SEVEN_ZIP_BLOCK_SIZE },
            blocks: Vec::new(),
            fetched: 0,
            requests: 0,
            limit: self.limit,
        };
        let outcome = match &job.kind {
            Kind::SevenZipSfx => self.extract_seven_zip(&job, &mut reader),
            Kind::Zip { path: Some(path) } => self.extract_zip(&job, &mut reader, path),
            Kind::Zip { path: None } => Ok(None),
        };
        result.file_size = (reader.len > 0).then_some(reader.base + reader.len);
        result.bytes = reader.fetched;
        result.requests = reader.requests;
        match outcome {
            Ok(Some((path, inspection))) => {
                result.state = "done";
                result.nested_path = Some(path);
                result.inspection = Some(inspection);
            }
            Ok(None) => {
                result.state = "no_target";
            }
            Err(e) => result.error = Some(format!("{e:#}")),
        }
        result
    }

    fn extract_zip(&self, job: &Job, reader: &mut RangeReader, path: &str) -> Result<Option<(String, pe::Inspection)>> {
        if reader.len == 0 {
            reader.len = reader.remote_size().context("cannot read the file size")?;
        }
        let mut archive = zip::ZipArchive::new(&mut *reader).context("cannot read zip directory")?;
        let Some(index) =
            (0..archive.len()).find(|&i| archive.name_for_index(i).is_some_and(|n| n.eq_ignore_ascii_case(path)))
        else {
            debug!("{}: no {path} in zip", job.url);
            return Ok(None);
        };
        let mut entry = archive.by_index(index)?;
        let name = entry.name().to_string();
        let (bytes, layout, complete) = pe::read_stub(&mut entry, pe::MAX_HEAD_BYTES)?;
        Ok(Some((name, self.save_nested(&job.sha256, &bytes, layout, complete)?)))
    }

    fn save_nested(&self, sha256: &str, bytes: &[u8], layout: Layout, complete: bool) -> Result<pe::Inspection> {
        let nested = self.heads_dir.join(&sha256[..2]).join(format!("{sha256}.nested.head"));
        std::fs::create_dir_all(nested.parent().expect("head path has a parent"))?;
        std::fs::write(&nested, bytes).with_context(|| format!("cannot write {}", nested.display()))?;
        let mut inspection = match layout {
            Layout::SectionsEnd(_) => pe::inspect(bytes),
            _ => pe::Inspection { detected_type: "not_pe", ..Default::default() },
        };
        if !complete && inspection.detected_type == "pe" {
            inspection.detected_type = "pe_partial";
        }
        Ok(inspection)
    }

    fn extract_seven_zip(&self, job: &Job, reader: &mut RangeReader) -> Result<Option<(String, pe::Inspection)>> {
        let head_path = self.heads_dir.join(&job.sha256[..2]).join(format!("{}.head", job.sha256));
        let head = std::fs::read(&head_path).with_context(|| format!("cannot read {}", head_path.display()))?;
        let target = sfx_target(&head);

        let offset = match find(&head, SEVEN_ZIP_SIGNATURE) {
            Some(offset) => offset as u64,
            None => {
                let mut more = Vec::new();
                reader.seek(SeekFrom::Start(head.len() as u64))?;
                reader.take(SIGNATURE_SEARCH_BYTES).read_to_end(&mut more)?;
                let found = find(&more, SEVEN_ZIP_SIGNATURE).context("no 7-Zip archive found after the SFX stub")?;
                head.len() as u64 + found as u64
            }
        };
        reader.base = offset;
        reader.len = job.file_size.context("no file size from the probe")? - offset;
        reader.pos = 0;
        reader.blocks.clear();

        let password = Password::empty();
        let archive = Archive::read(reader, &password).context("cannot read 7-Zip archive headers")?;
        let Some(file_index) = archive.files.iter().position(|f| is_target(f, &target)) else {
            debug!("{}: no {target} in archive", job.url);
            return Ok(None);
        };
        let block_index = archive.stream_map.file_block_index[file_index].context("target file is empty")?;
        let path = archive.files[file_index].name().to_string();

        let mut stub = None;
        let decoder = BlockDecoder::new(1, block_index, &archive, &password, reader);
        decoder.for_each_entries(&mut |entry, data| {
            if is_target(entry, &target) {
                stub = Some(pe::read_stub(data, pe::MAX_HEAD_BYTES)?);
                return Ok(false);
            }
            io::copy(data, &mut io::sink())?;
            Ok(true)
        })?;
        let (bytes, layout, complete) = stub.context("target file was not decoded")?;
        Ok(Some((path, self.save_nested(&job.sha256, &bytes, layout, complete)?)))
    }
}

impl App {
    pub fn unpack(&mut self, options: UnpackOptions) -> Result<()> {
        let jobs = self.unpack_jobs(options.max_attempts, options.limit)?;
        if jobs.is_empty() {
            info!("Nothing to unpack");
            return Ok(());
        }
        info!("Unpacking {} files, {} at a time", jobs.len(), options.concurrency);

        let unpacker = Arc::new(Unpacker {
            client: self.client.clone(),
            handle: self.runtime.handle().clone(),
            heads_dir: self.data_dir.join("heads"),
            limit: options.max_mb * 1_000_000,
        });
        let total = jobs.len();
        let conn = &mut self.conn;
        let runtime = &self.runtime;
        let (sender, receiver) = mpsc::channel();

        std::thread::scope(|scope| {
            let writer = scope.spawn(move || write_results(conn, receiver, total));
            runtime.block_on(async {
                let permits = Arc::new(Semaphore::new(options.concurrency));
                let mut tasks = JoinSet::new();
                for job in jobs {
                    let (permits, unpacker, sender) = (permits.clone(), unpacker.clone(), sender.clone());
                    tasks.spawn(async move {
                        let _permit = permits.acquire_owned().await;
                        let result = tokio::task::spawn_blocking(move || unpacker.unpack(job)).await;
                        if let Ok(result) = result {
                            let _ = sender.send(result);
                        }
                    });
                }
                drop(sender);
                while tasks.join_next().await.is_some() {}
            });
            writer.join().expect("result writer panicked")
        })
    }

    fn unpack_jobs(&self, max_attempts: u32, limit: Option<usize>) -> Result<Vec<Job>> {
        let mut seven_zip = self.conn.prepare(&format!(
            "SELECT sha256, url, file_size FROM files f
             WHERE detected_type = '7z_sfx' AND description LIKE '%Self-extracting Archive%'
               AND file_size IS NOT NULL
               AND (unpack_state IS NULL OR (unpack_state = 'failed' AND unpack_attempts < ?1))
               AND {PROBE_SCOPE}
             ORDER BY file_size"
        ))?;
        let mut zip = self.conn.prepare(
            "SELECT f.sha256, f.url, f.file_size, MIN(e.nested_path) FROM files f
             JOIN manifest_entries e ON e.sha256 = f.sha256 AND e.is_latest AND NOT e.locale_variant
             WHERE e.installer_type = 'zip' AND e.nested_installer_type IN ('nullsoft', 'exe')
               AND (f.unpack_state IS NULL OR (f.unpack_state = 'failed' AND f.unpack_attempts < ?1))
             GROUP BY f.sha256",
        )?;
        let size = |r: &rusqlite::Row| r.get::<_, Option<i64>>(2).map(|s| s.map(|s| s as u64));
        let mut jobs: Vec<Job> = seven_zip
            .query_map([max_attempts], |r| {
                Ok(Job { sha256: r.get(0)?, url: r.get(1)?, file_size: size(r)?, kind: Kind::SevenZipSfx })
            })?
            .collect::<Result<_, _>>()?;
        let zips = zip.query_map([max_attempts], |r| {
            Ok(Job { sha256: r.get(0)?, url: r.get(1)?, file_size: size(r)?, kind: Kind::Zip { path: r.get(3)? } })
        })?;
        jobs.extend(zips.collect::<Result<Vec<_>, _>>()?);
        jobs.truncate(limit.unwrap_or(usize::MAX));
        Ok(jobs)
    }
}

fn write_results(conn: &mut Connection, receiver: mpsc::Receiver<UnpackResult>, total: usize) -> Result<()> {
    let mut found = conn.prepare(
        "UPDATE files SET wrapper = ?9, wrapper_description = description, nested_path = ?2,
             detected_type = ?3, description = ?4, nsis_version = ?5, nsis_signature = ?6,
             probe_state = 'done', file_size = COALESCE(file_size, ?10),
             unpack_state = 'done', unpack_attempts = unpack_attempts + 1, unpack_error = NULL,
             unpack_bytes = ?7, unpack_requests = ?8
         WHERE sha256 = ?1",
    )?;
    let mut other = conn.prepare(
        "UPDATE files SET unpack_state = ?2, unpack_attempts = unpack_attempts + 1, unpack_error = ?3,
             unpack_bytes = ?4, unpack_requests = ?5,
             probe_state = CASE WHEN probe_state = 'pending' THEN 'failed' ELSE probe_state END,
             last_error = CASE WHEN probe_state = 'pending' THEN ?3 ELSE last_error END
         WHERE sha256 = ?1",
    )?;
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut done = 0usize;
    for r in receiver {
        let mb = r.bytes as f64 / 1e6;
        match &r.inspection {
            Some(i) => {
                found.execute(params![
                    r.sha256,
                    r.nested_path,
                    i.detected_type,
                    i.description,
                    i.nsis_version,
                    i.nsis_signature,
                    r.bytes as i64,
                    r.requests,
                    r.wrapper,
                    r.file_size.map(|s| s as i64),
                ])?;
                debug!("{}: {} {:?} after {mb:.1} MB", r.sha256, i.detected_type, i.nsis_version);
                *counts.entry(format!("{} {}", r.wrapper, i.detected_type)).or_default() += 1;
            }
            None => {
                other.execute(params![r.sha256, r.state, r.error, r.bytes as i64, r.requests])?;
                debug!("{}: {} after {mb:.1} MB: {}", r.sha256, r.state, r.error.as_deref().unwrap_or("-"));
                *counts.entry(format!("{} {}", r.wrapper, r.state)).or_default() += 1;
            }
        }
        done += 1;
        let mut summary: Vec<_> = counts.iter().map(|(k, v)| format!("{k} {v}")).collect();
        summary.sort();
        info!("Unpacked {done}/{total}: {}", summary.join(", "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::sfx_target;

    #[test]
    fn reads_run_program() {
        let head =
            b"MZ...;!@Install@!UTF-8!\r\nTitle=\"Mozilla Firefox\"\r\nRunProgram=\"setup.exe\"\r\n;!@InstallEnd@!7z";
        assert_eq!(sfx_target(head), "setup.exe");
    }

    #[test]
    fn reads_execute_file_with_path_and_arguments() {
        let head = b";!@Install@!UTF-8!\nExecuteFile=\"bin\\\\Install.exe\"\n;!@InstallEnd@!";
        assert_eq!(sfx_target(head), "Install.exe");
        let head = b";!@Install@!UTF-8!\nRunProgram=\"hidcon:installer.exe /S\"\n;!@InstallEnd@!";
        assert_eq!(sfx_target(head), "installer.exe");
    }

    #[test]
    fn defaults_to_setup_exe() {
        assert_eq!(sfx_target(b"no config"), "setup.exe");
    }
}
