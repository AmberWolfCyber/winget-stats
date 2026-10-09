use serde::Serialize;

use crate::version::Version;

/// A CVE that affects a range of NSIS versions.
#[derive(Debug, Serialize)]
pub struct Cve {
    pub id: &'static str,
    /// First affected version, inclusive.
    pub affected_from: Option<&'static str>,
    /// Last affected version, inclusive.
    pub last_affected: Option<&'static str>,
    /// First fixed version.
    pub fixed_in: Option<&'static str>,
}

pub const CVES: &[Cve] = &[
    Cve { id: "CVE-2026-42171", affected_from: Some("3.06.1"), last_affected: None, fixed_in: Some("3.12") },
    Cve { id: "CVE-2023-37378", affected_from: None, last_affected: None, fixed_in: Some("3.09") },
    Cve { id: "CVE-2025-43715", affected_from: None, last_affected: None, fixed_in: Some("3.11") },
];

impl Cve {
    pub fn affects(&self, version: &Version) -> bool {
        self.affected_from.is_none_or(|v| *version >= Version::parse(v))
            && self.last_affected.is_none_or(|v| *version <= Version::parse(v))
            && self.fixed_in.is_none_or(|v| *version < Version::parse(v))
    }

    pub fn range(&self) -> String {
        match (self.affected_from, self.last_affected, self.fixed_in) {
            (Some(from), Some(last), _) => format!("{from} to {last}"),
            (None, Some(last), _) => format!("{last} and earlier"),
            (Some(from), None, Some(fixed)) => format!("{from} to before {fixed}"),
            (None, None, Some(fixed)) => format!("Before {fixed}"),
            (Some(from), None, None) => format!("{from} and later"),
            (None, None, None) => "All versions".to_string(),
        }
    }
}

/// CVE IDs that affect an NSIS version, or `None` when the version is not a release number.
pub fn affected(nsis_version: &str) -> Option<Vec<&'static str>> {
    if !is_release(nsis_version) {
        return None;
    }
    let version = Version::parse(upstream_version(nsis_version));
    Some(CVES.iter().filter(|c| c.affects(&version)).map(|c| c.id).collect())
}

/// Removes a package revision such as "-4" or "-3+deb12u1", which Linux distributions add to makensis builds.
fn upstream_version(version: &str) -> &str {
    match version.split_once('-') {
        Some((upstream, revision)) if revision.starts_with(|c: char| c.is_ascii_digit()) => upstream,
        _ => version,
    }
}

/// True for versions such as "3.08" or "2.46.5-Unicode", false for development builds such as "27-Nov-2019.cvs".
fn is_release(version: &str) -> bool {
    let mut parts = version.split('-');
    let is_dated = parts.next().is_some_and(|d| d.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_some_and(|m| m.len() == 3 && m.bytes().all(|b| b.is_ascii_alphabetic()));
    version.starts_with(|c: char| c.is_ascii_digit()) && !is_dated && !version.ends_with(".cvs")
}

#[cfg(test)]
mod tests {
    use super::affected;

    fn ids(version: &str) -> Vec<&'static str> {
        affected(version).unwrap()
    }

    #[test]
    fn version_ranges() {
        assert_eq!(ids("2.46"), ["CVE-2023-37378", "CVE-2025-43715"]);
        assert_eq!(ids("3.06"), ["CVE-2023-37378", "CVE-2025-43715"]);
        assert_eq!(ids("3.06.1"), ["CVE-2026-42171", "CVE-2023-37378", "CVE-2025-43715"]);
        assert_eq!(ids("3.08"), ["CVE-2026-42171", "CVE-2023-37378", "CVE-2025-43715"]);
        assert_eq!(ids("3.09"), ["CVE-2026-42171", "CVE-2025-43715"]);
        assert_eq!(ids("3.10"), ["CVE-2026-42171", "CVE-2025-43715"]);
        assert_eq!(ids("3.11"), ["CVE-2026-42171"]);
        assert!(ids("3.12").is_empty());
        assert!(ids("3.13").is_empty());
    }

    #[test]
    fn suffixed_versions() {
        assert_eq!(ids("3.0rc2"), ["CVE-2023-37378", "CVE-2025-43715"]);
        assert_eq!(ids("2.46.5-Unicode"), ["CVE-2023-37378", "CVE-2025-43715"]);
        assert!(ids("3.12-1").is_empty());
        assert_eq!(ids("3.11.7461.309"), ["CVE-2026-42171"]);
        assert_eq!(ids("3.09-4"), ["CVE-2026-42171", "CVE-2025-43715"]);
        assert_eq!(ids("3.11-1"), ["CVE-2026-42171"]);
        assert_eq!(ids("3.06.1-1"), ["CVE-2026-42171", "CVE-2023-37378", "CVE-2025-43715"]);
        assert_eq!(ids("3.08-3+deb12u1"), ["CVE-2026-42171", "CVE-2023-37378", "CVE-2025-43715"]);
        assert!(ids("3.13.7497.330").is_empty());
    }

    #[test]
    fn development_builds_are_unknown() {
        assert_eq!(affected("27-Nov-2019.cvs"), None);
        assert_eq!(affected("31-Jul-2026.cvs"), None);
        assert_eq!(affected(""), None);
    }
}
