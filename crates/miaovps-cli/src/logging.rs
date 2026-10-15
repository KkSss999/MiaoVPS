//! Synchronous, bounded diagnostic logging. Never records arguments, keys or payloads.
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;
const BACKUPS: usize = 3;
pub const DEV_LOG: &str = "tunnel-dev.log";

pub fn init(dev_dir: Option<&Path>) -> anyhow::Result<()> {
    let console = tracing_subscriber::fmt::layer().with_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("miaovps=info")),
    );
    let file = dev_dir
        .map(|dir| -> anyhow::Result<_> {
            let path = dir.join(DEV_LOG);
            let writer = LogWriter(Arc::new(Mutex::new(RollingLog::open(path, MAX_LOG_BYTES)?)));
            Ok(tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_thread_names(true)
                .with_writer(writer)
                .with_filter(tracing_subscriber::EnvFilter::new(
                    "miaovps=debug,boringtun=debug",
                )))
        })
        .transpose()?;
    tracing_subscriber::registry()
        .with(console)
        .with(file)
        .try_init()?;
    if let Some(dir) = dev_dir {
        eprintln!(
            "详细日志: {}（16 MiB × 4，追加保存）",
            dir.join(DEV_LOG).display()
        );
        tracing::info!(
            pid = std::process::id(),
            version = env!("CARGO_PKG_VERSION"),
            "dev diagnostic session started"
        );
    }
    Ok(())
}

#[derive(Clone)]
struct LogWriter(Arc<Mutex<RollingLog>>);
struct LogGuard<'a>(MutexGuard<'a, RollingLog>);
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
    type Writer = LogGuard<'a>;
    fn make_writer(&'a self) -> Self::Writer {
        LogGuard(self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }
}
impl Write for LogGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.file.flush()
    }
}
struct RollingLog {
    path: PathBuf,
    file: File,
    size: u64,
    limit: u64,
}
fn open_private(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}
impl RollingLog {
    fn open(path: PathBuf, limit: u64) -> io::Result<Self> {
        let file = open_private(&path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path,
            file,
            size,
            limit,
        })
    }
    fn backup(&self, n: usize) -> PathBuf {
        self.path.with_extension(format!("log.{n}"))
    }
    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        for n in (1..BACKUPS).rev() {
            match std::fs::rename(self.backup(n), self.backup(n + 1)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        std::fs::rename(&self.path, self.backup(1))?;
        self.file = open_private(&self.path)?;
        self.size = self.file.metadata()?.len();
        Ok(())
    }
}
impl Write for RollingLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.size > 0 && self.size.saturating_add(buf.len() as u64) > self.limit {
            self.rotate()?;
        }
        self.file.write_all(buf)?;
        self.size += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn logs_append_across_restarts_and_rotate_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("miaovps-log-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join(DEV_LOG);
        {
            let mut log = RollingLog::open(path.clone(), 8).unwrap();
            log.write_all(b"first\n").unwrap();
        }
        let mut log = RollingLog::open(path.clone(), 8).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first\n");
        for _ in 0..6 {
            log.write_all(b"next\n").unwrap();
        }
        assert!(path.exists());
        for n in 1..=BACKUPS {
            let backup = log.backup(n);
            assert!(std::fs::metadata(&backup).unwrap().len() <= 8);
            assert_eq!(
                std::fs::metadata(backup).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(!log.backup(BACKUPS + 1).exists());
        drop(log);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn file_captures_app_and_protocol_debug_with_console_disabled() {
        let dir = std::env::temp_dir().join(format!("miaovps-filter-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join(DEV_LOG);
        let writer = LogWriter(Arc::new(Mutex::new(
            RollingLog::open(path.clone(), MAX_LOG_BYTES).unwrap(),
        )));
        let console = tracing_subscriber::fmt::layer()
            .with_writer(io::sink)
            .with_filter(tracing_subscriber::EnvFilter::new("off"));
        let file = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(writer)
            .with_filter(tracing_subscriber::EnvFilter::new(
                "miaovps=debug,boringtun=debug",
            ));
        let subscriber = tracing_subscriber::registry().with(console).with(file);
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "miaovps_connect", "app diagnostic");
            tracing::debug!(target: "boringtun::noise", "protocol diagnostic");
            tracing::debug!(target: "unrelated", "unrelated event");
        });
        let contents = std::fs::read_to_string(path).unwrap();
        assert!(contents.contains("app diagnostic"));
        assert!(contents.contains("protocol diagnostic"));
        assert!(!contents.contains("unrelated event"));
        assert!(!contents.contains('\u{1b}'));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
