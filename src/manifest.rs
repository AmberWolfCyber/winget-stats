use serde::Deserialize;

/// The fields of an installer or singleton manifest that the indexer uses.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InstallerManifest {
    pub package_identifier: String,
    pub package_version: String,
    pub installer_type: Option<String>,
    pub nested_installer_type: Option<String>,
    pub nested_installer_files: Option<Vec<NestedInstallerFile>>,
    pub scope: Option<String>,
    pub installer_locale: Option<String>,
    #[serde(default)]
    pub installers: Vec<Installer>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NestedInstallerFile {
    pub relative_file_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Installer {
    pub architecture: Option<String>,
    pub installer_type: Option<String>,
    pub nested_installer_type: Option<String>,
    pub nested_installer_files: Option<Vec<NestedInstallerFile>>,
    pub scope: Option<String>,
    pub installer_locale: Option<String>,
    pub installer_url: String,
    pub installer_sha256: String,
}

/// One installer with root-level values applied where the installer does not set its own.
#[derive(Debug)]
pub struct Entry {
    pub architecture: Option<String>,
    pub installer_type: Option<String>,
    pub nested_installer_type: Option<String>,
    /// Path of the installer inside a zip file, with forward slashes.
    pub nested_path: Option<String>,
    pub scope: Option<String>,
    pub installer_locale: Option<String>,
    pub url: String,
    pub sha256: String,
}

impl InstallerManifest {
    pub fn parse(text: &str) -> Result<Self, serde_norway::Error> {
        serde_norway::from_str(text.trim_start_matches('\u{feff}'))
    }

    pub fn entries(&self) -> impl Iterator<Item = Entry> + '_ {
        let lower =
            |own: &Option<String>, root: &Option<String>| own.as_ref().or(root.as_ref()).map(|s| s.to_lowercase());
        self.installers.iter().map(move |i| Entry {
            architecture: i.architecture.as_ref().map(|s| s.to_lowercase()),
            installer_type: lower(&i.installer_type, &self.installer_type),
            nested_installer_type: lower(&i.nested_installer_type, &self.nested_installer_type),
            nested_path: i
                .nested_installer_files
                .as_ref()
                .or(self.nested_installer_files.as_ref())
                .and_then(|files| files.first())
                .map(|f| f.relative_file_path.trim().replace('\\', "/").trim_start_matches("./").to_string()),
            scope: lower(&i.scope, &self.scope),
            installer_locale: i.installer_locale.clone().or_else(|| self.installer_locale.clone()),
            url: i.installer_url.trim().to_string(),
            sha256: i.installer_sha256.trim().to_lowercase(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::InstallerManifest;

    const SAMPLE: &str = "\u{feff}PackageIdentifier: Example.App
PackageVersion: 1.10
InstallerType: nullsoft
Scope: machine
Installers:
- Architecture: x86
  InstallerUrl: https://example.com/a.exe
  InstallerSha256: ABCDEF
- Architecture: x64
  InstallerType: msi
  Scope: user
  InstallerUrl: https://example.com/b.msi
  InstallerSha256: 012345
ManifestType: installer
ManifestVersion: 1.12.0
";

    const ZIP_SAMPLE: &str = "PackageIdentifier: Example.Zip
PackageVersion: 2.0
InstallerType: zip
NestedInstallerType: nullsoft
NestedInstallerFiles:
- RelativeFilePath: bin\\setup.exe
Installers:
- Architecture: x64
  InstallerUrl: https://example.com/a.zip
  InstallerSha256: ABCDEF
";

    #[test]
    fn nested_installer_path() {
        let m = InstallerManifest::parse(ZIP_SAMPLE).unwrap();
        let entry = m.entries().next().unwrap();
        assert_eq!(entry.nested_installer_type.as_deref(), Some("nullsoft"));
        assert_eq!(entry.nested_path.as_deref(), Some("bin/setup.exe"));
    }

    #[test]
    fn unquoted_version_keeps_text() {
        let m = InstallerManifest::parse(SAMPLE).unwrap();
        assert_eq!(m.package_version, "1.10");
    }

    #[test]
    fn root_values_apply_to_installers() {
        let m = InstallerManifest::parse(SAMPLE).unwrap();
        let entries: Vec<_> = m.entries().collect();
        assert_eq!(entries[0].installer_type.as_deref(), Some("nullsoft"));
        assert_eq!(entries[0].scope.as_deref(), Some("machine"));
        assert_eq!(entries[0].sha256, "abcdef");
        assert_eq!(entries[1].installer_type.as_deref(), Some("msi"));
        assert_eq!(entries[1].scope.as_deref(), Some("user"));
    }
}
