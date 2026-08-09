use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct SearchScope<'a> {
    pub root: &'a Path,
    pub file_type: Option<&'a str>,
    pub glob: Option<&'a str>,
    pub hidden: bool,
    pub no_ignore: bool,
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: PathBuf,
    pub relative_path: String,
}

/// The discoverable paths for one traversal policy, plus cheap evidence that
/// the traversal inputs have not changed. Contents are deliberately absent.
#[derive(Debug, Clone)]
pub struct FileInventory {
    pub entries: Vec<FileEntry>,
    pub freshness: FreshnessManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshnessManifest {
    pub root: FileStamp,
    pub directories: Vec<(PathBuf, FileStamp)>,
    pub policy_files: Vec<(PathBuf, FileStamp)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStamp {
    pub modified: Option<SystemTime>,
    pub len: u64,
    pub is_dir: bool,
    pub content_digest: u64,
}

#[derive(Debug, Clone)]
pub struct TextFile {
    pub path: PathBuf,
    pub relative_path: String,
    pub text: String,
}

pub fn collect_file_entries(scope: &SearchScope<'_>) -> Vec<FileEntry> {
    let mut builder = WalkBuilder::new(scope.root);
    builder.hidden(!scope.hidden);
    if scope.no_ignore {
        builder.git_ignore(false);
        builder.git_global(false);
        builder.git_exclude(false);
        builder.ignore(false);
    }

    let file_type = scope.file_type.map(normalize_file_type);
    let glob = scope.glob.and_then(build_glob);
    let mut files = Vec::new();

    for entry in builder.build() {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(expected_ext) = file_type.as_deref()
            && path.extension().and_then(|s| s.to_str()) != Some(expected_ext)
        {
            continue;
        }
        let relative_path = normalize_display_path(scope.root, path);
        if let Some(glob) = &glob
            && !glob.is_match(&relative_path)
        {
            continue;
        }

        files.push(FileEntry {
            path: path.to_path_buf(),
            relative_path,
        });
    }

    files
}

pub fn collect_file_inventory(scope: &SearchScope<'_>) -> FileInventory {
    let entries = collect_file_entries(scope);
    let mut directories = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for result in WalkBuilder::new(scope.root).hidden(!scope.hidden).build() {
        let Ok(entry) = result else { continue };
        if entry.path().is_dir() {
            seen.insert(entry.path().to_path_buf());
        }
    }
    for dir in seen {
        if let Some(stamp) = file_stamp(&dir) {
            directories.push((dir, stamp));
        }
    }
    directories.sort_by(|a, b| a.0.cmp(&b.0));
    let policy_files = policy_paths(scope.root)
        .into_iter()
        .filter_map(|path| file_stamp(&path).map(|stamp| (path, stamp)))
        .collect();
    FileInventory {
        entries,
        freshness: FreshnessManifest {
            root: file_stamp(scope.root).unwrap_or(FileStamp {
                modified: None,
                len: 0,
                is_dir: true,
                content_digest: 0,
            }),
            directories,
            policy_files,
        },
    }
}

pub fn inventory_is_fresh(root: &Path, manifest: &FreshnessManifest) -> bool {
    file_stamp(root) == Some(manifest.root.clone())
        && manifest
            .directories
            .iter()
            .all(|(path, stamp)| file_stamp(path) == Some(stamp.clone()))
        && policy_paths(root)
            .into_iter()
            .filter_map(|path| file_stamp(&path).map(|stamp| (path, stamp)))
            .collect::<Vec<_>>()
            == manifest.policy_files
}

fn file_stamp(path: &Path) -> Option<FileStamp> {
    let metadata = fs::metadata(path).ok()?;
    Some(FileStamp {
        modified: metadata.modified().ok(),
        len: metadata.len(),
        is_dir: metadata.is_dir(),
        content_digest: if metadata.is_file() {
            digest_file(path)
        } else {
            digest_directory(path)
        },
    })
}

fn digest_file(path: &Path) -> u64 {
    let Ok(bytes) = fs::read(path) else { return 0 };
    bytes.iter().fold(1469598103934665603u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(1099511628211)
    })
}

fn digest_directory(path: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    let mut names = entries
        .filter_map(|entry| {
            entry
                .ok()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
        })
        .collect::<Vec<_>>();
    names.sort();
    names
        .iter()
        .flat_map(|name| name.as_bytes())
        .fold(1469598103934665603u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(1099511628211)
        })
}

fn policy_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for result in WalkBuilder::new(root)
        .hidden(true)
        .standard_filters(false)
        .build()
    {
        let Ok(entry) = result else { continue };
        if entry.path().is_dir() {
            paths.extend([
                entry.path().join(".gitignore"),
                entry.path().join(".ignore"),
                entry.path().join(".rgignore"),
            ]);
        }
    }
    paths.push(root.join(".git/info/exclude"));
    if let Ok(global) = std::env::var("XDG_CONFIG_HOME") {
        paths.push(PathBuf::from(global).join("git/ignore"));
    } else if let Ok(home) = std::env::var("HOME") {
        paths.push(PathBuf::from(home).join(".config/git/ignore"));
    }
    paths.sort();
    paths.dedup();
    paths
}

pub fn read_text_file(path: &Path) -> Option<String> {
    let Ok(bytes) = fs::read(path) else {
        return None;
    };
    if bytes.contains(&0) {
        return None;
    }

    match String::from_utf8(bytes) {
        Ok(text) => Some(text),
        Err(err) => Some(String::from_utf8_lossy(err.as_bytes()).into_owned()),
    }
}

pub fn collect_text_files(scope: &SearchScope<'_>) -> Vec<TextFile> {
    let mut files = Vec::new();

    for entry in collect_file_entries(scope) {
        let Some(text) = read_text_file(&entry.path) else {
            continue;
        };

        files.push(TextFile {
            path: entry.path,
            relative_path: entry.relative_path,
            text,
        });
    }

    files
}

fn build_glob(glob: &str) -> Option<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    builder.add(Glob::new(glob).ok()?);
    builder.build().ok()
}

pub fn normalize_file_type(file_type: &str) -> String {
    match file_type {
        "rust" => "rs".to_string(),
        "javascript" => "js".to_string(),
        "typescript" => "ts".to_string(),
        other => other.trim_start_matches('.').to_string(),
    }
}

pub fn normalize_display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}
