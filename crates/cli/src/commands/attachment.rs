//! `attachment list|get|add`.

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, bail};
use pwk_api::{AttachmentRef, MAX_ATTACHMENT_SIZE};

use super::Context;
use super::client::with_api;
use super::resolve::Resolver;
use crate::cli::AttachmentCommand;
use crate::fsutil;
use crate::output::{self, Format, Table};

/// `attachment …`.
pub fn run(ctx: &Context, cmd: &AttachmentCommand) -> anyhow::Result<ExitCode> {
    with_api(ctx, |api| {
        let r = Resolver::new(&api.client);
        match cmd {
            AttachmentCommand::List { item } => {
                let item = r.item(item, None)?;
                if ctx.format == Format::Json {
                    output::print_json(&item.attachments)?;
                } else {
                    let mut table = Table::new(["NAME", "ID"]);
                    for a in &item.attachments {
                        table.push([a.name.clone(), a.id.clone()]);
                    }
                    table.print()?;
                }
            }
            AttachmentCommand::Get {
                item,
                attachment,
                output,
            } => {
                let item = r.item(item, None)?;
                let Some(found) = AttachmentRef::find(&item, attachment) else {
                    let names: Vec<&str> =
                        item.attachments.iter().map(|a| a.name.as_str()).collect();
                    bail!(
                        "item `{}` has no attachment `{attachment}`; available: {}",
                        item.name,
                        if names.is_empty() {
                            "none".to_owned()
                        } else {
                            names.join(", ")
                        }
                    );
                };
                let (name, data) = api
                    .client
                    .download_attachment(&item, &found.id)
                    .with_context(|| format!("cannot download attachment `{}`", found.name))?;
                save(ctx, output.as_deref(), &name, &data)?;
            }
            AttachmentCommand::Add { item, file, name } => {
                let name = match name {
                    Some(n) => n.clone(),
                    None => file_name(file)?,
                };
                let data = read_upload(file)?;
                let item = r.item(item, None)?;
                api.client
                    .add_attachment(&item, &name, &data)
                    .with_context(|| format!("cannot add attachment `{name}`"))?;
                ctx.info(&format!(
                    "attached `{name}` ({} bytes) to item `{}`",
                    data.len(),
                    item.name
                ));
            }
        }
        Ok(ExitCode::SUCCESS)
    })
}

/// Reads a file to upload. The size is checked before reading (so a huge file is not
/// loaded into memory) and again on the bytes read (the file may grow meanwhile).
pub fn read_upload(path: &Path) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    use std::io::Read as _;
    let too_big = |size: u64| {
        anyhow::anyhow!(
            "{} is {size} bytes; attachments may have at most {MAX_ATTACHMENT_SIZE} bytes",
            path.display()
        )
    };
    let file =
        std::fs::File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    let size = file
        .metadata()
        .with_context(|| format!("cannot read {}", path.display()))?
        .len();
    let limit = MAX_ATTACHMENT_SIZE as u64;
    if size > limit {
        return Err(too_big(size));
    }
    let mut data = zeroize::Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut data)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if data.len() > MAX_ATTACHMENT_SIZE {
        return Err(too_big(data.len() as u64));
    }
    Ok(data)
}

/// The last component of `path` as UTF-8.
fn file_name(path: &Path) -> anyhow::Result<String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        .with_context(|| format!("{} has no usable file name; pass --name", path.display()))
}

/// Where `attachment get` writes to.
#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    /// stdout.
    Stdout,
    /// An explicitly named file (replaced).
    File(PathBuf),
    /// The attachment's own name in the current directory (never replaced).
    NewFile(PathBuf),
}

/// Decides the target: `-o -` or a non-terminal stdout without `-o` mean stdout, `-o
/// PATH` a file; otherwise the attachment's file name (stripped to its last component).
pub fn target(
    output: Option<&Path>,
    name: &str,
    stdout_is_terminal: bool,
) -> anyhow::Result<Target> {
    match output {
        Some(p) if p == Path::new("-") => Ok(Target::Stdout),
        Some(p) => Ok(Target::File(p.to_path_buf())),
        None if !stdout_is_terminal => Ok(Target::Stdout),
        None => {
            let base = Path::new(name)
                .file_name()
                .filter(|n| !n.is_empty() && *n != "." && *n != "..")
                .with_context(|| {
                    format!("attachment name `{name}` is not a file name; pass -o PATH")
                })?;
            Ok(Target::NewFile(PathBuf::from(base)))
        }
    }
}

fn save(ctx: &Context, output: Option<&Path>, name: &str, data: &[u8]) -> anyhow::Result<()> {
    match target(output, name, std::io::stdout().is_terminal())? {
        Target::Stdout => {
            let mut out = std::io::stdout().lock();
            out.write_all(data)
                .and_then(|()| out.flush())
                .context("cannot write to stdout")?;
        }
        Target::File(path) => {
            fsutil::write_atomic(&path, data)
                .with_context(|| format!("cannot write {}", path.display()))?;
            ctx.info(&format!(
                "saved `{name}` to {} ({} bytes)",
                path.display(),
                data.len()
            ));
        }
        Target::NewFile(path) => {
            let mut file = create_new_private(&path)?;
            file.write_all(data)
                .and_then(|()| file.sync_all())
                .with_context(|| format!("cannot write {}", path.display()))?;
            ctx.info(&format!(
                "saved `{name}` to {} ({} bytes)",
                path.display(),
                data.len()
            ));
        }
    }
    Ok(())
}

/// Creates `path` with mode 0600, refusing to replace an existing file.
fn create_new_private(path: &Path) -> anyhow::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!(
                "{} exists already; pass -o PATH to choose another file",
                path.display()
            )
        } else {
            anyhow::Error::new(e).context(format!("cannot create {}", path.display()))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(
            target(Some(Path::new("-")), "a.txt", true).unwrap(),
            Target::Stdout
        );
        assert_eq!(target(None, "a.txt", false).unwrap(), Target::Stdout);
        assert_eq!(
            target(Some(Path::new("out.bin")), "a.txt", false).unwrap(),
            Target::File("out.bin".into())
        );
        assert_eq!(
            target(None, "../../etc/passwd", true).unwrap(),
            Target::NewFile("passwd".into())
        );
        assert!(target(None, "..", true).is_err());
    }

    #[test]
    fn upload_size_is_checked_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        // Sparse, so the test stays cheap; reading it all would take 1 GiB of memory.
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(1 << 30).unwrap();
        let err = read_upload(&path).unwrap_err().to_string();
        assert!(err.contains("1073741824 bytes"), "{err}");
        file.set_len(MAX_ATTACHMENT_SIZE as u64).unwrap();
        assert_eq!(read_upload(&path).unwrap().len(), MAX_ATTACHMENT_SIZE);
        file.set_len(MAX_ATTACHMENT_SIZE as u64 + 1).unwrap();
        assert!(read_upload(&path).is_err());
        assert!(read_upload(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x");
        std::fs::write(&path, b"old").unwrap();
        let err = create_new_private(&path).unwrap_err().to_string();
        assert!(err.contains("exists already"), "{err}");
        let fresh = dir.path().join("y");
        drop(create_new_private(&fresh).unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
