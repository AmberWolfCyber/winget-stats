# winget-stats

winget-stats finds the NSIS installers in the [winget community repository](https://github.com/microsoft/winget-pkgs) and records the NSIS version that built each one. It tags each version with known NSIS CVEs and shows the results in a dashboard.

The tool does not download full installers. An NSIS installer starts with a small stub program, about 40 to 700 KB. The stub holds the PE headers and a manifest with the NSIS version. The tool fetches only this stub with HTTP range requests, so a full run uses about 3 GB, compared with about 900 GB for full downloads.

The tool covers the latest version of each package only.

## Build

You need a Rust toolchain.

```
cargo build --release
```

The binary is `target/release/winget-stats`. It has no runtime dependencies. The dashboard HTML is compiled into the binary.

## Usage

Run the phases in this order. Each phase stores its results in a SQLite database. If a run stops, run the same command again and it continues from where it stopped.

```
winget-stats index      # read the winget-pkgs manifests into the database
winget-stats probe      # fetch the stub of each installer and read its NSIS version
winget-stats unpack     # read installers inside 7-Zip SFX archives and zip files
winget-stats status     # show counts and CVE totals
winget-stats serve      # open the dashboard at http://127.0.0.1:8642
winget-stats export     # write the dashboard as static files to public/
```

All commands accept these options:

| Option | Description |
|---|---|
| `-d`, `--data-dir` | Folder for the database, the manifest archive and the saved installer heads. The default is `data`. |
| `-p`, `--proxy` | HTTP proxy as `ip:port`. TLS certificate checks are off when you set a proxy. |
| `-v`, `--verbose` | Show debug output. |

Run `winget-stats <command> --help` for the options of each command.

## Phases

### index

The index phase downloads a tarball of winget-pkgs (about 130 MB) to `data/winget-pkgs.tar.gz`. Use `--refresh` to get a new copy. It reads all installer manifests from the tarball with no extraction to disk.

The phase stores every installer of every version. It marks the latest version of each package with the winget version ordering, so `1.10` is later than `1.9`.

Installers become candidates for the later phases when their winget type is `nullsoft` or `exe`, or when they are zip files with a nested `nullsoft` or `exe` installer. Winget uses the type `nullsoft` for NSIS.

Mozilla publishes one package per language, such as `Mozilla.Firefox.de`. The index marks these language builds, and the later phases skip them. The base package, such as `Mozilla.Firefox`, stays in scope.

### probe

The probe phase fetches the start of each candidate installer with a range request. It reads the PE section table, then fetches up to the end of the last section plus 4 KB, with a limit of 1 MiB. It saves these bytes to `data/heads/<xx>/<sha256>.head`.

The probe detects NSIS in two ways:

- The application manifest has the description `Nullsoft Install System v<version>`. This gives the NSIS version.
- The NSIS header (`0xDEADBEEF` followed by `NullsoftInst`) is at a 512-byte boundary. NSIS installers without a manifest are found this way, but their version is unknown.

The probe also records other results:

| Result | Meaning |
|---|---|
| `nsis` | An NSIS installer |
| `7z_sfx` | A 7-Zip self-extracting archive. The unpack phase reads the installer inside it. |
| `pe` | Another type of PE file |
| `pe_partial` | A PE file whose sections end past the 1 MiB limit. These are not NSIS stubs. |
| `not_pe` | Not a PE file. Usually an HTML page from a broken download link. |

The default is 32 requests at the same time, and 8 to one host. The probe retries timeouts, HTTP 429 and HTTP 5xx responses. It does not retry HTTP 404 and 410, and it records these files as `gone`. Other failed files are tried again on the next run, up to 3 runs.

### unpack

Some NSIS installers are inside another file. The unpack phase reads them with range requests too.

7-Zip self-extracting archives are used by Firefox, Thunderbird, SeaMonkey and many browsers based on Firefox. The unpack phase reads the SFX config to find the program that it runs, usually `setup.exe`. It reads the archive's file list from the end of the file, then decompresses the archive until it has the stub of that program.

Most of these archives are solid, and `setup.exe` is near the end. The phase must fetch almost the whole file to decompress it, so a Firefox installer costs about its full size of 80 to 90 MB. The 74 files in the current data cost about 5 GB. Use `--max-mb` to set a limit per file. The default is 200 MB.

Zip files are not solid. The phase reads the zip's file list, then decompresses only the start of the installer that the manifest names in `NestedInstallerFiles`. Each zip file costs about 0.5 MB.

The phase saves the stub of the inner installer to `data/heads/<xx>/<sha256>.nested.head`. The dashboard shows these files as "NSIS in 7-Zip SFX" or "NSIS in zip".

### inspect

The inspect phase runs the detection again on the saved head files. It sends no network requests. Run it after a change to the detection rules.

### status

The status phase shows counts for each phase, the most common NSIS versions and the number of packages affected by each CVE.

## CVE tagging

The CVE rules are in `src/cve.rs`. Each rule has a first affected version, a last affected version or a first fixed version.

| CVE | Affected versions |
|---|---|
| CVE-2026-42171 | 3.06.1 to before 3.12 |
| CVE-2023-37378 | Before 3.09 |
| CVE-2025-43715 | Before 3.11 |

To add a CVE, add one line to the `CVES` table. The dashboard and `status` both read this table.

The matching follows these rules:

- Versions are compared with the winget ordering, so `3.06.1` is later than `3.06`.
- Pre-releases such as `3.0rc2` are earlier than the release.
- Linux distributions build makensis with a package revision, such as `3.09-4` or `3.08-3+deb12u1`. The tool removes the revision before it compares. A distribution can backport a fix without a change to the version, so these results can be wrong.
- Development builds such as `27-Nov-2019.cvs` have an unknown CVE status.

## Dashboard

`winget-stats serve` starts a local web server with the dashboard. The dashboard shows:

- The number of packages and files that use NSIS
- The NSIS versions by package count, with release and development builds in different colours
- The packages affected by each CVE
- A comparison of the winget installer type with the detected type
- A list of installers that you can search and filter by result, NSIS version and CVE

Select a version bar or a CVE to filter the installer list.

## Hosting

The dashboard needs only static files. The database stays on your machine for the analysis.

`winget-stats export` writes `public/index.html` and five files in `public/api/`. The total is about 3.3 MB. The repository includes the `public` folder, and GitLab Pages publishes it.

GitLab Pages publishes only the output of a CI job. The `pages` job in `.gitlab-ci.yml` does not build anything. It publishes the `public` folder from the commit, and it runs only on the default branch.

To update the site:

```
winget-stats index --refresh
winget-stats probe
winget-stats unpack
winget-stats export
git add public
git commit -m "Update dashboard data"
git push
```

The `public` folder also works on any other static host, such as Cloudflare Pages.

The page lists named products with the CVEs in their installers. Before you publish it, think about coordinated disclosure with the affected vendors. To keep the page private, keep the project private and turn on Pages access control.

## Data

| Path | Contents |
|---|---|
| `data/winget-pkgs.tar.gz` | The winget-pkgs snapshot |
| `data/winget-stats.db` | The SQLite database |
| `data/heads/` | The saved installer stubs, about 2.8 GB |
| `public/` | The exported dashboard, published by GitLab Pages |

The database has three tables:

| Table | Contents |
|---|---|
| `manifest_entries` | One row for each installer in each package version |
| `files` | One row for each candidate file, by SHA256, with the probe and unpack results |
| `meta` | The winget-pkgs commit and the time of the last index run |

To list the NSIS packages with their versions:

```sql
SELECT DISTINCT e.package_id, e.version, f.nsis_version
FROM files f JOIN manifest_entries e ON e.sha256 = f.sha256 AND e.is_latest AND NOT e.locale_variant
WHERE f.detected_type = 'nsis'
ORDER BY f.nsis_version;
```

## Limits

- The tool reads only the start of each file, so it cannot check the SHA256 from the manifest. If a vendor replaced the file at the same URL, the results are for the new file.
- Some download servers do not support range requests. The tool skips zip files on these servers.
- The tool does not look inside WiX Burn bundles, WinRAR archives or 7-Zip archives without an SFX manifest. Some of these can contain NSIS installers.
- The NSIS version comes from the installer's manifest. A vendor can change this text after the build.

## Development

```
cargo test
cargo clippy --all-targets
cargo fmt
```

The code uses a line length of 120, set in `rustfmt.toml`.

| File | Contents |
|---|---|
| `src/main.rs` | Command-line parsing |
| `src/app.rs` | Shared state (HTTP client, runtime, database) and `status` |
| `src/db.rs` | Database schema and shared query filters |
| `src/index.rs` | The index phase |
| `src/manifest.rs` | Winget manifest parsing |
| `src/version.rs` | Winget version ordering |
| `src/probe.rs` | The probe phase |
| `src/pe.rs` | PE parsing and NSIS detection |
| `src/unpack.rs` | The unpack phase and the HTTP range reader |
| `src/inspect.rs` | The inspect phase |
| `src/cve.rs` | CVE rules |
| `src/serve.rs` | The dashboard server and `export` |
| `src/dashboard.html` | The dashboard page |
