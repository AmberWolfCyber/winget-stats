use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::params;
use tar::EntryType;
use tracing::{debug, info, warn};

use crate::app::App;
use crate::manifest::InstallerManifest;
use crate::version::Version;

const TARBALL_URL: &str = "https://codeload.github.com/microsoft/winget-pkgs/tar.gz/refs/heads/master";

/// Installer types that can hold an NSIS installer.
const CANDIDATE_TYPES: &str = "'nullsoft', 'exe'";

/// Publishers with one package per language, such as "Mozilla.Firefox.de" next to "Mozilla.Firefox".
const LOCALE_VARIANT_PREFIXES: &[&str] = &["Mozilla."];

#[derive(Default)]
struct Scan {
    commit: Option<String>,
    manifests: Vec<InstallerManifest>,
    parse_errors: usize,
}

impl App {
    pub fn index(&mut self, tarball: Option<PathBuf>, refresh: bool) -> Result<()> {
        let tarball = match tarball {
            Some(path) => path,
            None => {
                let path = self.data_dir.join("winget-pkgs.tar.gz");
                if refresh || !path.exists() {
                    self.fetch_tarball(&path)?;
                }
                path
            }
        };

        let started = Instant::now();
        let scan = read_manifests(&tarball)?;
        info!(
            "Parsed {} manifests in {:.1}s ({} failed)",
            scan.manifests.len(),
            started.elapsed().as_secs_f64(),
            scan.parse_errors
        );
        self.store(&scan)
    }

    fn fetch_tarball(&self, path: &Path) -> Result<()> {
        info!("Downloading {TARBALL_URL}");
        let part = path.with_extension("gz.part");
        let mut file = File::create(&part).with_context(|| format!("cannot create {}", part.display()))?;
        let size = self.runtime.block_on(async {
            let mut response = self.client.get(TARBALL_URL).send().await?.error_for_status()?;
            let mut size = 0usize;
            while let Some(chunk) = response.chunk().await? {
                file.write_all(&chunk)?;
                size += chunk.len();
            }
            anyhow::Ok(size)
        })?;
        drop(file);
        std::fs::rename(&part, path)?;
        info!("Saved {} ({:.1} MB)", path.display(), size as f64 / 1e6);
        Ok(())
    }

    fn store(&mut self, scan: &Scan) -> Result<()> {
        let mut latest: HashMap<String, (Version, usize)> = HashMap::new();
        for (i, m) in scan.manifests.iter().enumerate() {
            let version = Version::parse(&m.package_version);
            let key = m.package_identifier.to_lowercase();
            match latest.get(&key) {
                Some((best, _)) if *best >= version => {}
                _ => {
                    latest.insert(key, (version, i));
                }
            }
        }
        let is_latest: Vec<bool> = {
            let mut flags = vec![false; scan.manifests.len()];
            for (_, i) in latest.values() {
                flags[*i] = true;
            }
            flags
        };

        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM manifest_entries", [])?;
        let mut entries = 0usize;
        {
            let mut insert = tx.prepare(
                "INSERT INTO manifest_entries (package_id, version, is_latest, locale_variant, architecture, scope,
                     installer_locale, installer_type, nested_installer_type, nested_path, url, sha256)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )?;
            for (m, latest) in scan.manifests.iter().zip(&is_latest) {
                let locale_variant = is_locale_variant(&m.package_identifier);
                for e in m.entries() {
                    insert.execute(params![
                        m.package_identifier,
                        m.package_version,
                        latest,
                        locale_variant,
                        e.architecture,
                        e.scope,
                        e.installer_locale,
                        e.installer_type,
                        e.nested_installer_type,
                        e.nested_path,
                        e.url,
                        e.sha256,
                    ])?;
                    entries += 1;
                }
            }
        }

        // Latest entries go first so that a file shared across versions gets its newest URL
        let new_files = tx.execute(
            &format!(
                "INSERT INTO files (sha256, url)
                 SELECT sha256, url FROM manifest_entries
                 WHERE installer_type IN ({CANDIDATE_TYPES})
                    OR (installer_type = 'zip' AND nested_installer_type IN ({CANDIDATE_TYPES}))
                 ORDER BY is_latest DESC
                 ON CONFLICT (sha256) DO NOTHING"
            ),
            [],
        )?;

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs().to_string();
        let mut meta = tx.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)")?;
        meta.execute(params!["indexed_at", now])?;
        meta.execute(params!["source_commit", scan.commit.as_deref().unwrap_or("unknown")])?;
        drop(meta);
        tx.commit()?;

        info!("Stored {entries} entries for {} packages, {new_files} new candidate files", latest.len());
        Ok(())
    }
}

fn read_manifests(tarball: &Path) -> Result<Scan> {
    info!("Reading {}", tarball.display());
    let file = File::open(tarball).with_context(|| format!("cannot open {}", tarball.display()))?;
    let gz = flate2::read::GzDecoder::new(BufReader::with_capacity(1 << 20, file));
    let mut archive = tar::Archive::new(gz);
    let mut scan = Scan::default();
    let mut text = String::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type() == EntryType::XGlobalHeader {
            text.clear();
            entry.read_to_string(&mut text)?;
            scan.commit = text.lines().find_map(|l| l.split_once("comment=").map(|(_, c)| c.trim().to_string()));
            continue;
        }
        if !entry.header().entry_type().is_file() {
            continue;
        }

        let path = entry.path()?.into_owned();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !is_manifest_path(&path) || !name.ends_with(".yaml") || name.contains(".locale.") {
            continue;
        }

        text.clear();
        if let Err(e) = entry.read_to_string(&mut text) {
            warn!("Cannot read {}: {e}", path.display());
            scan.parse_errors += 1;
            continue;
        }
        // Skip version manifests, which share the "<id>.yaml" name with singleton manifests
        if !name.ends_with(".installer.yaml") && !text.contains("ManifestType: singleton") {
            continue;
        }

        match InstallerManifest::parse(&text) {
            Ok(m) => scan.manifests.push(m),
            Err(e) => {
                debug!("Cannot parse {}: {e}", path.display());
                scan.parse_errors += 1;
            }
        }
    }
    Ok(scan)
}

/// True when the path is "<root>/manifests/...".
fn is_manifest_path(path: &Path) -> bool {
    let mut parts = path.components().filter(|c| matches!(c, Component::Normal(_)));
    parts.next();
    parts.next().is_some_and(|c| c.as_os_str() == "manifests")
}

fn is_locale_variant(package_id: &str) -> bool {
    let Some(last) = package_id.rsplit('.').next() else { return false };
    let language = last.split('-').next().unwrap_or(last);
    LOCALE_VARIANT_PREFIXES.iter().any(|p| package_id.starts_with(p))
        && (2..=3).contains(&language.len())
        && language.bytes().all(|b| b.is_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::is_locale_variant;

    #[test]
    fn locale_variants() {
        assert!(is_locale_variant("Mozilla.Firefox.de"));
        assert!(is_locale_variant("Mozilla.Firefox.ESR.es-MX"));
        assert!(is_locale_variant("Mozilla.Thunderbird.ca-valencia"));
        assert!(!is_locale_variant("Mozilla.Firefox"));
        assert!(!is_locale_variant("Mozilla.Firefox.ESR"));
        assert!(!is_locale_variant("Mozilla.mozregression"));
        assert!(!is_locale_variant("Example.App.de"));
    }
}
