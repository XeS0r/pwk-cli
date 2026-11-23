//! `pwk run`: start a command with resolved secrets in its environment and, optionally,
//! mask those secrets in its output.

use std::io::{self, Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use zeroize::Zeroizing;

/// Replacement for a secret in the child's output.
pub const CONCEALED: &[u8] = b"<concealed by pwk>";

/// The set of secrets to mask (longest first, so overlapping secrets are fully hidden).
#[derive(Clone, Default)]
pub struct Masker {
    secrets: Vec<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for Masker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Masker")
            .field("secrets", &self.secrets.len())
            .finish()
    }
}

impl Masker {
    /// A masker for `secrets`; empty ones are ignored, duplicates removed.
    pub fn new<I, S>(secrets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        let mut list: Vec<Zeroizing<Vec<u8>>> = secrets
            .into_iter()
            .map(|s| s.as_ref().to_vec())
            .filter(|s| !s.is_empty())
            .map(Zeroizing::new)
            .collect();
        list.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        list.dedup();
        Self { secrets: list }
    }

    /// True without secrets (nothing to mask).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// A streaming replacer for one output stream.
    #[must_use]
    pub fn stream(&self) -> StreamMasker<'_> {
        StreamMasker {
            masker: self,
            pending: Vec::new(),
        }
    }
}

/// Masks secrets in a byte stream that arrives in arbitrary chunks. Bytes that could be
/// the start of a secret are held back until the next chunk decides.
#[derive(Debug)]
pub struct StreamMasker<'a> {
    masker: &'a Masker,
    pending: Vec<u8>,
}

impl StreamMasker<'_> {
    /// Feeds `chunk`; returns the output that is final now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        self.process(false)
    }

    /// Ends the stream; returns the rest of the output. Also used to release held-back
    /// bytes after an idle period (the stream can continue afterwards).
    pub fn finish(&mut self) -> Vec<u8> {
        self.process(true)
    }

    /// True while bytes are held back as a possible start of a secret.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    fn process(&mut self, eof: bool) -> Vec<u8> {
        let buf = Zeroizing::new(std::mem::take(&mut self.pending));
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        'scan: while i < buf.len() {
            let rest = &buf[i..];
            for secret in &self.masker.secrets {
                if rest.starts_with(secret) {
                    // Longest complete match wins, unless a longer secret is still
                    // undecided (checked below before we get here: list is longest first).
                    out.extend_from_slice(CONCEALED);
                    i += secret.len();
                    continue 'scan;
                }
                if !eof && rest.len() < secret.len() && secret.starts_with(rest) {
                    // Could become this (longer) secret with the next chunk.
                    break 'scan;
                }
            }
            out.push(buf[i]);
            i += 1;
        }
        self.pending = buf[i..].to_vec();
        out
    }
}

/// Exit code for the child's status: its code, or 128 + signal on Unix.
#[must_use]
pub fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

/// Whether `name` carries unlock material that `run` must not hand to the child:
/// `PWK_SESSION`, every `PWK_SESSION_*`, `PASSWORK_MASTER_KEY`, `PASSWORK_TOKEN` and
/// `PASSWORK_REFRESH_TOKEN`. (`PASSWORK_HOST` is not secret and stays.)
#[must_use]
pub fn is_unlock_variable(name: &str) -> bool {
    name == "PWK_SESSION"
        || name.starts_with("PWK_SESSION_")
        || matches!(
            name,
            "PASSWORK_MASTER_KEY" | "PASSWORK_TOKEN" | "PASSWORK_REFRESH_TOKEN"
        )
}

/// How long held-back bytes (a possible secret prefix) wait for more output before
/// they are written as they are.
pub const IDLE_FLUSH: Duration = Duration::from_millis(50);

/// How long the output pipes may still be drained after the child exited. A grandchild
/// that keeps the pipes open must not keep `pwk` waiting.
pub const EXIT_GRACE: Duration = Duration::from_millis(200);

/// Runs `argv` with `env` added to the inherited environment (minus the unlock
/// variables, see [`is_unlock_variable`]) and returns its exit code. stdin is
/// inherited. With a non-empty `masker`, stdout and stderr are piped through it.
pub fn run_command(
    argv: &[String],
    env: &[(String, Zeroizing<String>)],
    masker: Option<&Masker>,
) -> anyhow::Result<i32> {
    let (program, args) = argv.split_first().context("no command given")?;
    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::inherit());
    for (key, _) in std::env::vars_os() {
        if key.to_str().is_some_and(is_unlock_variable) {
            command.env_remove(&key);
        }
    }
    for (key, value) in env {
        command.env(key, value.as_str());
    }
    let masker = masker.filter(|m| !m.is_empty());
    let Some(masker) = masker else {
        let status = command
            .status()
            .with_context(|| format!("cannot run `{program}`"))?;
        return Ok(exit_code(status));
    };

    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| format!("cannot run `{program}`"))?;
    let stdout = child.stdout.take().context("child stdout")?;
    let stderr = child.stderr.take().context("child stderr")?;
    // The readers are detached: a grandchild may keep a pipe open long after the child
    // exited, and their blocking read must not hold up `pwk`.
    let (out_tx, out_rx) = mpsc::channel();
    let (err_tx, err_rx) = mpsc::channel();
    spawn_reader(stdout, out_tx.clone());
    spawn_reader(stderr, err_tx.clone());
    let status = thread::scope(|scope| {
        let out = scope.spawn(move || pump_channel(&out_rx, io::stdout(), masker, IDLE_FLUSH));
        let err = scope.spawn(move || pump_channel(&err_rx, io::stderr(), masker, IDLE_FLUSH));
        let status = child.wait();
        let deadline = Instant::now() + EXIT_GRACE;
        let _ = out_tx.send(Chunk::ChildExited(deadline));
        let _ = err_tx.send(Chunk::ChildExited(deadline));
        let _ = out.join();
        let _ = err.join();
        status
    })
    .with_context(|| format!("cannot wait for `{program}`"))?;
    Ok(exit_code(status))
}

/// A message to [`pump_channel`].
#[derive(Debug)]
pub enum Chunk {
    /// Output of the child.
    Data(Zeroizing<Vec<u8>>),
    /// The pipe reached its end (or failed).
    Eof,
    /// The child exited: drain until this deadline, then stop.
    ChildExited(Instant),
}

/// Reads `reader` on a detached thread and sends its output to `tx`, then [`Chunk::Eof`].
pub fn spawn_reader(mut reader: impl Read + Send + 'static, tx: Sender<Chunk>) {
    thread::spawn(move || {
        let mut buf = Zeroizing::new(vec![0u8; 8192]);
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx
                        .send(Chunk::Data(Zeroizing::new(buf[..n].to_vec())))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        let _ = tx.send(Chunk::Eof);
    });
}

/// Writes the chunks from `rx` to `writer`, masking secrets. Bytes held back as a
/// possible secret prefix are written once no new output arrived for `idle`. Stops at
/// [`Chunk::Eof`], or at the deadline of [`Chunk::ChildExited`]. Stops quietly when the
/// writer fails.
pub fn pump_channel(
    rx: &Receiver<Chunk>,
    mut writer: impl Write,
    masker: &Masker,
    idle: Duration,
) -> io::Result<()> {
    let mut stream = masker.stream();
    let mut deadline: Option<Instant> = None;
    loop {
        // Checked on every round: a grandchild that keeps writing never lets a receive
        // time out.
        if deadline.is_some_and(|d| Instant::now() >= d) {
            break;
        }
        let idle_wait = stream.has_pending().then_some(idle);
        let deadline_wait = deadline.map(|d| d.saturating_duration_since(Instant::now()));
        let wait = match (idle_wait, deadline_wait) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let message = match wait {
            Some(wait) => rx.recv_timeout(wait),
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match message {
            Ok(Chunk::Data(data)) => {
                let out = stream.push(&data);
                if !out.is_empty() {
                    writer.write_all(&out)?;
                    writer.flush()?;
                }
            }
            Ok(Chunk::Eof) | Err(RecvTimeoutError::Disconnected) => break,
            Ok(Chunk::ChildExited(at)) => deadline = Some(at),
            Err(RecvTimeoutError::Timeout) => {
                // Idle: nothing completed the possible secret, release the bytes.
                writer.write_all(&stream.finish())?;
                writer.flush()?;
            }
        }
    }
    writer.write_all(&stream.finish())?;
    writer.flush()
}

/// Copies `reader` to `writer` until its end, masking secrets (see [`pump_channel`]).
pub fn pump(
    reader: impl Read + Send + 'static,
    writer: impl Write,
    masker: &Masker,
) -> io::Result<()> {
    let (tx, rx) = mpsc::channel();
    spawn_reader(reader, tx);
    pump_channel(&rx, writer, masker, IDLE_FLUSH)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask_chunks(secrets: &[&str], chunks: &[&str]) -> String {
        let masker = Masker::new(secrets);
        let mut stream = masker.stream();
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(stream.push(chunk.as_bytes()));
        }
        out.extend(stream.finish());
        String::from_utf8(out).unwrap()
    }

    fn mask_bytewise(secrets: &[&str], text: &str) -> String {
        let masker = Masker::new(secrets);
        let mut stream = masker.stream();
        let mut out = Vec::new();
        for b in text.as_bytes() {
            out.extend(stream.push(&[*b]));
        }
        out.extend(stream.finish());
        String::from_utf8(out).unwrap()
    }

    const C: &str = "<concealed by pwk>";

    #[test]
    fn masks_within_chunk() {
        assert_eq!(
            mask_chunks(&["hunter2"], &["pw=hunter2 ok"]),
            format!("pw={C} ok")
        );
    }

    #[test]
    fn masks_across_chunks() {
        assert_eq!(
            mask_chunks(&["hunter2"], &["pw=hun", "te", "r2 and hunter", "2"]),
            format!("pw={C} and {C}")
        );
        assert_eq!(
            mask_bytewise(&["hunter2", "s3cr3t"], "a hunter2 b s3cr3t c hunter s3cr"),
            format!("a {C} b {C} c hunter s3cr")
        );
    }

    #[test]
    fn longest_secret_wins() {
        assert_eq!(
            mask_bytewise(&["abc", "abcdef"], "xabcdefy"),
            format!("x{C}y")
        );
        assert_eq!(
            mask_bytewise(&["abc", "abcdef"], "xabcdy"),
            format!("x{C}dy")
        );
        assert_eq!(mask_chunks(&["abc", "abcdef"], &["xabc"]), format!("x{C}"));
    }

    #[test]
    fn partial_prefix_is_released() {
        let masker = Masker::new(["secret"]);
        let mut stream = masker.stream();
        assert_eq!(stream.push(b"a sec"), b"a ");
        assert_eq!(stream.push(b"ond"), b"second");
        assert_eq!(stream.push(b" sec"), b" ");
        assert_eq!(stream.finish(), b"sec");
    }

    #[test]
    fn overlapping_start() {
        // "aab" where the secret is "ab": the first "a" is not a match start.
        assert_eq!(mask_bytewise(&["ab"], "aab"), format!("a{C}"));
        assert_eq!(mask_bytewise(&["aab"], "aaab"), format!("a{C}"));
    }

    #[test]
    fn empty_secrets_ignored() {
        let masker = Masker::new(["", ""]);
        assert!(masker.is_empty());
        assert_eq!(mask_chunks(&[""], &["text"]), "text");
    }

    #[test]
    fn multiline_secret() {
        assert_eq!(
            mask_chunks(&["line1\nline2"], &["x line1\n", "line2 y"]),
            format!("x {C} y")
        );
    }

    #[test]
    fn pump_masks() {
        let masker = Masker::new(["pass"]);
        let mut out = Vec::new();
        pump(&b"my pass is pass!"[..], &mut out, &masker).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), format!("my {C} is {C}!"));
    }

    #[test]
    fn unlock_variables() {
        for name in [
            "PWK_SESSION",
            "PWK_SESSION_WORK",
            "PWK_SESSION_MY_TEAM",
            "PASSWORK_MASTER_KEY",
            "PASSWORK_TOKEN",
            "PASSWORK_REFRESH_TOKEN",
        ] {
            assert!(is_unlock_variable(name), "{name}");
        }
        for name in ["PASSWORK_HOST", "PWK_PROFILE", "PWK_SESSIONX", "HOME", "DB"] {
            assert!(!is_unlock_variable(name), "{name}");
        }
    }

    /// A `Write` whose content the test can look at while the pump runs.
    #[derive(Clone, Default)]
    struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn data(text: &str) -> Chunk {
        Chunk::Data(Zeroizing::new(text.as_bytes().to_vec()))
    }

    #[test]
    fn held_back_prefix_is_flushed_when_idle() {
        let masker = Masker::new(["secret"]);
        let (tx, rx) = mpsc::channel();
        let out = Shared::default();
        thread::scope(|scope| {
            let writer = out.clone();
            let masker = &masker;
            let pump = scope.spawn(move || pump_channel(&rx, writer, masker, IDLE_FLUSH));
            // A prompt that ends like the start of a secret is shown after the idle time.
            tx.send(data("Password: sec")).unwrap();
            let start = Instant::now();
            while out.text() != "Password: sec" {
                assert!(start.elapsed() < Duration::from_secs(5), "{}", out.text());
                thread::sleep(Duration::from_millis(5));
            }
            assert!(start.elapsed() >= IDLE_FLUSH);
            // A secret split across chunks within the idle window is still masked.
            tx.send(data("\nx se")).unwrap();
            tx.send(data("cret y")).unwrap();
            tx.send(Chunk::Eof).unwrap();
            pump.join().unwrap().unwrap();
        });
        assert_eq!(out.text(), format!("Password: sec\nx {C} y"));
    }

    #[test]
    fn pump_stops_after_the_grace_period() {
        let masker = Masker::new(["secret"]);
        let (tx, rx) = mpsc::channel();
        let out = Shared::default();
        tx.send(data("done se")).unwrap();
        tx.send(Chunk::ChildExited(
            Instant::now() + Duration::from_millis(100),
        ))
        .unwrap();
        // No Eof ever arrives (a grandchild holds the pipe) and the sender stays alive.
        let start = Instant::now();
        pump_channel(&rx, out.clone(), &masker, Duration::from_secs(60)).unwrap();
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_eq!(out.text(), "done se");
        drop(tx);
    }

    #[test]
    fn pump_stops_at_the_deadline_while_output_keeps_coming() {
        // A grandchild writes continuously after the child exited: data is always ready,
        // so the deadline must be checked even when no receive times out.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let (tx, rx) = mpsc::channel();
        tx.send(Chunk::ChildExited(
            Instant::now() + Duration::from_millis(100),
        ))
        .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let feeder = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if tx.send(data("yyyyyyyy\n")).is_err() {
                        break;
                    }
                }
            })
        };
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let masker = Masker::new(["secret"]);
            let result = pump_channel(&rx, io::sink(), &masker, IDLE_FLUSH);
            let _ = done_tx.send(result.is_ok());
        });
        let finished = done_rx.recv_timeout(Duration::from_secs(5));
        stop.store(true, Ordering::Relaxed);
        assert_eq!(finished, Ok(true), "pump did not stop at the deadline");
        feeder.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn grandchild_holding_the_pipe_does_not_hang() {
        let masker = Masker::new(["never-printed"]);
        let start = Instant::now();
        let code = run_command(
            &["sh".into(), "-c".into(), "(sleep 30 &) ; echo done".into()],
            &[],
            Some(&masker),
        )
        .unwrap();
        assert_eq!(code, 0);
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{:?}",
            start.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn exit_codes() {
        let code = run_command(&["sh".into(), "-c".into(), "exit 7".into()], &[], None).unwrap();
        assert_eq!(code, 7);
        let code = run_command(
            &["sh".into(), "-c".into(), "kill -TERM $$".into()],
            &[],
            None,
        )
        .unwrap();
        assert_eq!(code, 128 + 15);
        let env = [("PWK_TEST_X".to_owned(), Zeroizing::new("v".to_owned()))];
        let masker = Masker::new(["v"]);
        let code = run_command(
            &["sh".into(), "-c".into(), "test \"$PWK_TEST_X\" = v".into()],
            &env,
            Some(&masker),
        )
        .unwrap();
        assert_eq!(code, 0);
        assert!(run_command(&["/nonexistent/pwk-test".into()], &[], None).is_err());
    }
}
