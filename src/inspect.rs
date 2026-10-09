use std::collections::BTreeMap;

use anyhow::Result;
use rusqlite::params;
use tracing::{info, warn};

use crate::app::App;
use crate::pe::{self, Layout};

impl App {
    /// Runs the detection again on the saved head files, with no network requests.
    pub fn inspect(&mut self) -> Result<()> {
        let heads_dir = self.data_dir.join("heads");
        let rows: Vec<(String, Option<String>, String)> = {
            let mut stmt = self.conn.prepare(
                "SELECT sha256, wrapper, detected_type FROM files
                 WHERE probe_state = 'done' AND detected_type IS NOT NULL AND detected_type != 'not_pe'",
            )?;
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?
        };

        let tx = self.conn.transaction()?;
        let mut changes: BTreeMap<(String, &'static str), usize> = BTreeMap::new();
        let mut missing = 0usize;
        {
            let mut update = tx.prepare(
                "UPDATE files SET detected_type = ?2, description = ?3, nsis_version = ?4, nsis_signature = ?5
                 WHERE sha256 = ?1",
            )?;
            for (sha256, wrapper, old_type) in &rows {
                let name = if wrapper.is_some() { format!("{sha256}.nested.head") } else { format!("{sha256}.head") };
                let Ok(bytes) = std::fs::read(heads_dir.join(&sha256[..2]).join(name)) else {
                    missing += 1;
                    continue;
                };
                let Layout::SectionsEnd(end) = pe::layout(&bytes) else { continue };
                let mut inspection = pe::inspect(&bytes);
                if end + pe::OVERLAY_BYTES > pe::MAX_HEAD_BYTES && inspection.detected_type == "pe" {
                    inspection.detected_type = "pe_partial";
                }
                if inspection.detected_type != old_type {
                    *changes.entry((old_type.clone(), inspection.detected_type)).or_default() += 1;
                }
                update.execute(params![
                    sha256,
                    inspection.detected_type,
                    inspection.description,
                    inspection.nsis_version,
                    inspection.nsis_signature,
                ])?;
            }
        }
        tx.commit()?;

        info!("Inspected {} files", rows.len() - missing);
        if missing > 0 {
            warn!("{missing} files have no saved head file");
        }
        for ((from, to), count) in &changes {
            info!("  {from} -> {to}: {count}");
        }
        Ok(())
    }
}
