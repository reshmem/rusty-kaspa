use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

/// Simple audit writer that appends lines to a file (best-effort).
pub struct AuditWriter {
    file: Mutex<std::fs::File>,
}

impl AuditWriter {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file: Mutex::new(file) })
    }

    pub fn append_line(&self, line: &str) {
        if let Ok(mut file) = self.file.lock() {
            let _ = writeln!(file, "{line}");
            let _ = file.flush();
        }
    }
}
