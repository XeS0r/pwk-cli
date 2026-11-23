//! Private files and directories: atomic replacement with fixed permissions.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

/// Creates `dir` and its missing parents; `dir` itself gets mode 0700 on Unix
/// (an existing directory keeps its mode).
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    match builder.create(dir) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => Ok(()),
        other => other,
    }
}

/// Creates a new file at `path` with mode 0600 on Unix; fails if anything (a file or a
/// symlink, which is not followed) already exists there.
fn create_new_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// How often [`write_atomic`] picks a new temporary name when one is taken.
const TEMP_ATTEMPTS: usize = 8;

/// Creates a fresh temporary file `.<name>.tmp.<random>` in `dir`.
fn create_temp(dir: &Path, name: &std::ffi::OsStr) -> io::Result<(PathBuf, File)> {
    let mut last = None;
    for _ in 0..TEMP_ATTEMPTS {
        let suffix: String = pwk_crypto::generate_salt()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(16)
            .collect();
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(name);
        tmp_name.push(format!(".tmp.{suffix}"));
        let tmp = dir.join(tmp_name);
        match create_new_private_file(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("no free temporary file name")))
}

/// Symlink hops [`resolve_destination`] follows before giving up (as Linux `ELOOP`).
const MAX_SYMLINK_HOPS: usize = 40;

/// The file that writing to `path` should replace: `path` itself, or, if it is a
/// symlink, the file it points to (followed through further links, relative targets
/// resolved against the link's directory; a dangling link yields its target path).
fn resolve_destination(path: &Path) -> io::Result<PathBuf> {
    let mut current = path.to_path_buf();
    for _ in 0..MAX_SYMLINK_HOPS {
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let target = fs::read_link(&current)?;
                current = match current.parent() {
                    Some(dir) if target.is_relative() => dir.join(target),
                    _ => target,
                };
            }
            _ => return Ok(current),
        }
    }
    Err(io::Error::other(format!(
        "{}: too many levels of symbolic links",
        path.display()
    )))
}

/// Replaces `path` with `data` atomically: writes a new temporary file (random name,
/// created exclusively with mode 0600, so no existing file or symlink is reused) in the
/// same directory, fsyncs it, renames it over `path` and fsyncs the directory. The
/// temporary file is removed on error.
///
/// If `path` is a symlink (a config managed by home-manager or stow), the link stays
/// and its target is replaced instead, with the temporary file in the target's
/// directory. Following the link at the destination is intended (it is the user's own
/// path); the temporary file never follows one.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let resolved = resolve_destination(path)?;
    let path = resolved.as_path();
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let (tmp, mut file) = create_temp(dir, name)?;

    let result = (|| {
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        return result;
    }
    #[cfg(unix)]
    if let Ok(dir) = File::open(dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_replaces_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.txt");
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        // No temp files left behind.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_ignores_planted_temp_names() {
        // The old fixed name `.f.txt.tmp.<pid>` as a symlink to a victim file: neither
        // followed nor reused.
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"keep").unwrap();
        let path = dir.path().join("f.txt");
        let planted = dir
            .path()
            .join(format!(".f.txt.tmp.{}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &planted).unwrap();
        write_atomic(&path, b"secret").unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert_eq!(fs::read(&path).unwrap(), b"secret");
        assert!(
            fs::symlink_metadata(&planted)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        // Only f.txt, victim and the planted link.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_keeps_a_symlinked_destination() {
        // config.toml managed by home-manager/stow: a link into another directory.
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let conf = dir.path().join("conf");
        fs::create_dir(&store).unwrap();
        fs::create_dir(&conf).unwrap();
        let target = store.join("config.toml");
        fs::write(&target, b"old").unwrap();
        let link = conf.join("config.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        write_atomic(&link, b"new").unwrap();
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&target).unwrap(), b"new");
        // No temp files left behind in either directory.
        assert_eq!(fs::read_dir(&store).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&conf).unwrap().count(), 1);

        // A relative link through a second link.
        let link2 = conf.join("second");
        std::os::unix::fs::symlink("config.toml", &link2).unwrap();
        write_atomic(&link2, b"newer").unwrap();
        assert!(
            fs::symlink_metadata(&link2)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&target).unwrap(), b"newer");

        // A dangling (relative) link: the file is created at the link target.
        let dangling = conf.join("out.txt");
        std::os::unix::fs::symlink("../store/out.txt", &dangling).unwrap();
        write_atomic(&dangling, b"fresh").unwrap();
        assert!(
            fs::symlink_metadata(&dangling)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(store.join("out.txt")).unwrap(), b"fresh");

        // A symlink loop is an error, not a hang.
        let a = conf.join("a");
        let b = conf.join("b");
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();
        assert!(write_atomic(&a, b"x").is_err());
    }

    #[test]
    fn write_atomic_cleans_up_on_error() {
        let dir = tempfile::tempdir().unwrap();
        // Renaming a file over a non-empty directory fails.
        let target = dir.path().join("d");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("x"), b"x").unwrap();
        assert!(write_atomic(&target, b"data").is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn temp_names_are_random() {
        let dir = tempfile::tempdir().unwrap();
        let (a, _) = create_temp(dir.path(), std::ffi::OsStr::new("f")).unwrap();
        let (b, _) = create_temp(dir.path(), std::ffi::OsStr::new("f")).unwrap();
        assert_ne!(a, b);
        let name = a.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with(".f.tmp.") && name.len() == ".f.tmp.".len() + 16);
    }

    #[cfg(unix)]
    #[test]
    fn private_modes() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a/b");
        create_private_dir(&sub).unwrap();
        let mode = fs::metadata(&sub).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let path = sub.join("secret");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&path, b"y").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
