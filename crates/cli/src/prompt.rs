//! Reading secrets and confirmations from the terminal or stdin.

use std::io::{self, BufRead, Write};

use anyhow::{Context as _, bail};
use pwk_crypto::SecretString;
use zeroize::Zeroizing;

/// Asks for a secret on the terminal (`/dev/tty`) without echo.
pub fn read_hidden(prompt: &str) -> anyhow::Result<SecretString> {
    let value = rpassword::prompt_password(prompt).with_context(
        || "cannot read from the terminal; pass the secret on stdin with the --…-stdin option",
    )?;
    Ok(Zeroizing::new(value))
}

/// `url` as a clickable link (OSC 8) when stderr is a terminal, else as plain text. The
/// visible text is the URL itself, so terminals without OSC 8 still show (and often
/// auto-link) it.
#[must_use]
pub fn link(url: &str) -> String {
    use std::io::IsTerminal as _;
    let dumb = std::env::var_os("TERM").is_some_and(|t| t == "dumb");
    if io::stderr().is_terminal() && !dumb {
        osc8(url)
    } else {
        url.to_owned()
    }
}

/// The OSC 8 hyperlink escape for `url`, showing the URL as text.
#[must_use]
fn osc8(url: &str) -> String {
    format!("\x1b]8;;{url}\x1b\\{url}\x1b]8;;\x1b\\")
}

/// Reads one line from stdin (`--password-stdin` and friends); the trailing newline is
/// removed. Empty input is an error.
pub fn read_secret_stdin(what: &str) -> anyhow::Result<SecretString> {
    read_secret_line(io::stdin().lock(), what)
}

/// [`read_secret_stdin`] from any reader.
pub fn read_secret_line(mut reader: impl BufRead, what: &str) -> anyhow::Result<SecretString> {
    let mut line = Zeroizing::new(String::new());
    reader
        .read_line(&mut line)
        .with_context(|| format!("cannot read the {what} from stdin"))?;
    let trimmed = line.strip_suffix('\n').unwrap_or(&line);
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    if trimmed.is_empty() {
        bail!("no {what} on stdin");
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}

/// Asks `question [y/N]` on the terminal; true for `y`/`yes`.
pub fn confirm(question: &str) -> anyhow::Result<bool> {
    #[cfg(unix)]
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty");
    #[cfg(not(unix))]
    let tty: io::Result<std::fs::File> = Err(io::Error::other("no terminal"));
    let tty = tty.context("cannot ask for confirmation without a terminal")?;
    let reader = io::BufReader::new(tty.try_clone()?);
    confirm_with(reader, tty, question)
}

/// [`confirm`] with explicit input and output.
pub fn confirm_with(
    mut input: impl BufRead,
    mut output: impl Write,
    question: &str,
) -> anyhow::Result<bool> {
    write!(output, "{question} [y/N] ")?;
    output.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc8_link() {
        assert_eq!(
            osc8("https://pw.example.com"),
            "\x1b]8;;https://pw.example.com\x1b\\https://pw.example.com\x1b]8;;\x1b\\"
        );
    }

    #[test]
    fn secret_line() {
        let read = |s: &str| read_secret_line(s.as_bytes(), "password");
        assert_eq!(read("pw\n").unwrap().as_str(), "pw");
        assert_eq!(read("pw\r\nmore\n").unwrap().as_str(), "pw");
        assert_eq!(read("no newline").unwrap().as_str(), "no newline");
        assert_eq!(read(" spaced \n").unwrap().as_str(), " spaced ");
        assert!(read("").unwrap_err().to_string().contains("no password"));
        assert!(read("\n").is_err());
    }

    #[test]
    fn confirmation() {
        let mut out = Vec::new();
        assert!(confirm_with("y\n".as_bytes(), &mut out, "Delete?").unwrap());
        assert_eq!(out, b"Delete? [y/N] ");
        assert!(confirm_with("YES\n".as_bytes(), Vec::new(), "q").unwrap());
        assert!(!confirm_with("\n".as_bytes(), Vec::new(), "q").unwrap());
        assert!(!confirm_with("".as_bytes(), Vec::new(), "q").unwrap());
        assert!(!confirm_with("nope\n".as_bytes(), Vec::new(), "q").unwrap());
    }
}
