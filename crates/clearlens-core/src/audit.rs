use crate::config::{ensure_private_dir, set_private_file_mode};
use crate::models::AuditRecord;
use crate::platform::resolve_home_dir;
use crate::safety::is_metadata_reparse_or_symlink;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

pub fn audit_log_path() -> PathBuf {
    resolve_home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".clearlens")
        .join("audit.jsonl")
}

pub fn append_audit_record(record: &AuditRecord) -> std::io::Result<()> {
    let path = audit_log_path();
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if is_metadata_reparse_or_symlink(&meta) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refusing to write audit log through symlink",
            ));
        }
    }
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    set_private_file_mode(&path);
    let line = serde_json::to_string(record).map_err(|e| std::io::Error::other(e.to_string()))?;
    writeln!(file, "{line}")?;
    Ok(())
}

pub fn read_audit_history(limit: usize) -> Vec<AuditRecord> {
    if limit == 0 {
        return Vec::new();
    }
    let path = audit_log_path();
    let Ok(mut file) = fs::File::open(path) else {
        return Vec::new();
    };

    // Bounded tail read so multi-MB long-lived audit logs never allocate O(total_history)
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let max_tail_bytes = ((limit as u64).saturating_mul(1024)).max(65_536);
    if file_len > max_tail_bytes {
        let _ = file.seek(SeekFrom::End(-(max_tail_bytes as i64)));
        let mut reader = BufReader::new(file);
        // Discard partial first line after mid-file seek
        let mut partial = String::new();
        let _ = reader.read_line(&mut partial);
        let mut buf = String::new();
        let _ = reader.read_to_string(&mut buf);
        let mut items: Vec<AuditRecord> = buf
            .lines()
            .filter_map(|line| serde_json::from_str::<AuditRecord>(line).ok())
            .collect();
        items.reverse();
        items.truncate(limit);
        return items;
    }

    let reader = BufReader::new(file);
    let mut items: Vec<AuditRecord> = reader
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str::<AuditRecord>(&line).ok())
        .collect();
    items.reverse();
    items.truncate(limit);
    items
}
