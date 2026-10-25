use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use security_monitor_ai::redact_text;
use tracing_subscriber::fmt::MakeWriter;

const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_LOG_FILES: usize = 4;
const MAX_LOG_LINE_BYTES: usize = 64 * 1024;

pub(super) fn initialize(directory: &Path) -> io::Result<()> {
    let writer = RotatingLog::new(directory, MAX_LOG_BYTES, MAX_LOG_FILES)?;
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_target(true)
        .with_writer(writer)
        .finish();
    tracing::subscriber::set_global_default(subscriber).map_err(io::Error::other)
}

#[derive(Clone)]
struct RotatingLog {
    path: PathBuf,
    state: Arc<Mutex<LogState>>,
    max_bytes: u64,
    max_files: usize,
}

struct LogState {
    file: Option<File>,
    current_bytes: u64,
}

impl RotatingLog {
    fn new(directory: &Path, max_bytes: u64, max_files: usize) -> io::Result<Self> {
        fs::create_dir_all(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let path = directory.join("security-monitor.log");
        let file = open_log_file(&path)?;
        let current_bytes = file.metadata()?.len();
        Ok(Self {
            path,
            state: Arc::new(Mutex::new(LogState {
                file: Some(file),
                current_bytes,
            })),
            max_bytes: max_bytes.max(1),
            max_files: max_files.max(1),
        })
    }

    fn write_event(&self, bytes: &[u8]) -> io::Result<()> {
        let text = String::from_utf8_lossy(bytes);
        let mut line = redact_text(&text).text.replace(['\r', '\n'], " ");
        if line.len() > MAX_LOG_LINE_BYTES {
            let mut boundary = MAX_LOG_LINE_BYTES;
            while !line.is_char_boundary(boundary) {
                boundary -= 1;
            }
            line.truncate(boundary);
            line.push_str(" [truncated]");
        }
        line.push('\n');

        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("log writer lock poisoned"))?;
        if state.current_bytes > 0
            && state.current_bytes.saturating_add(line.len() as u64) > self.max_bytes
        {
            self.rotate(&mut state)?;
        }
        let file = state
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("log file unavailable"))?;
        file.write_all(line.as_bytes())?;
        state.current_bytes = state.current_bytes.saturating_add(line.len() as u64);
        Ok(())
    }

    fn rotate(&self, state: &mut LogState) -> io::Result<()> {
        if let Some(mut file) = state.file.take() {
            file.flush()?;
        }
        for index in (1..self.max_files.saturating_sub(1)).rev() {
            let source = self.rotation_path(index);
            let destination = self.rotation_path(index + 1);
            remove_if_exists(&destination)?;
            if source.exists() {
                fs::rename(source, destination)?;
            }
        }
        if self.max_files > 1 {
            let first = self.rotation_path(1);
            remove_if_exists(&first)?;
            if self.path.exists() {
                fs::rename(&self.path, &first)?;
            }
        } else {
            remove_if_exists(&self.path)?;
        }
        state.file = Some(open_log_file(&self.path)?);
        state.current_bytes = 0;
        Ok(())
    }

    fn rotation_path(&self, index: usize) -> PathBuf {
        PathBuf::from(format!("{}.{}", self.path.display(), index))
    }
}

fn open_log_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

impl<'a> MakeWriter<'a> for RotatingLog {
    type Writer = RedactingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            log: self.clone(),
            pending: Vec::new(),
        }
    }
}

struct RedactingWriter {
    log: RotatingLog,
    pending: Vec<u8>,
}

impl Write for RedactingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.log.write_event(&self.pending)?;
        self.pending.clear();
        Ok(())
    }
}

impl Drop for RedactingWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write};

    use tempfile::TempDir;

    use super::{RedactingWriter, RotatingLog};

    #[test]
    fn rotating_log_redacts_user_data_and_keeps_a_bounded_history() {
        let directory = TempDir::new().unwrap();
        let log = RotatingLog::new(directory.path(), 80, 2).unwrap();
        for message in [
            "operation failed for /Users/Alice/project/file.txt with api_key=secret-value",
            "request failed for alice@example.com",
            "second operation failed for /home/alice/workspace/repository",
        ] {
            let mut writer = RedactingWriter {
                log: log.clone(),
                pending: Vec::new(),
            };
            writer.write_all(message.as_bytes()).unwrap();
            writer.flush().unwrap();
        }

        let files = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap())
            .collect::<Vec<_>>();
        let all_logs = files.join("\n");
        assert_eq!(files.len(), 2);
        assert!(!all_logs.contains("Alice"));
        assert!(!all_logs.contains("secret-value"));
        assert!(!all_logs.contains("alice@example.com"));
        assert!(all_logs.contains("[REDACTED"));
    }

    #[test]
    fn formatted_tracing_events_are_redacted_before_persistence() {
        let directory = TempDir::new().unwrap();
        let log = RotatingLog::new(directory.path(), 4 * 1024, 4).unwrap();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_target(false)
            .with_writer(log)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(
                account = "alice@example.com",
                "failed at /Users/Alice/project"
            );
        });

        let contents = fs::read_to_string(directory.path().join("security-monitor.log")).unwrap();
        assert!(!contents.contains("alice@example.com"));
        assert!(!contents.contains("/Users/Alice"));
        assert!(contents.contains("[REDACTED"));
    }
}
