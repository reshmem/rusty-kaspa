use log::warn;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

/// Simple audit writer that appends lines to a file (best-effort).
pub struct AuditWriter {
    path: std::path::PathBuf,
    file: Mutex<std::fs::File>,
}

impl AuditWriter {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { path, file: Mutex::new(file) })
    }

    pub fn append_line(&self, line: &str) {
        match self.file.lock() {
            Ok(mut file) => {
                if let Err(err) = writeln!(file, "{line}") {
                    warn!("audit_writer: failed to write line path={} error={}", self.path.display(), err);
                    return;
                }
                if let Err(err) = file.flush() {
                    warn!("audit_writer: failed to flush line path={} error={}", self.path.display(), err);
                }
            }
            Err(err) => {
                warn!("audit_writer: failed to lock file mutex path={} error={}", self.path.display(), err);
            }
        }
    }
}
