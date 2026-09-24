//! Small durable file operations for the Bootstrap ownership transition.
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("missing parent directory")?;
    fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    let name = path
        .file_name()
        .ok_or("missing file name")?
        .to_string_lossy();
    let temporary = parent.join(format!(".{name}-{}.tmp", crate::identity::random_token()?));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| format!("create {}: {e}", temporary.display()))?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("persist {}: {e}", temporary.display()))?;
        fs::rename(&temporary, path).map_err(|e| format!("publish {}: {e}", path.display()))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| format!("persist {}: {e}", parent.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn remove(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => {
            let parent = path.parent().ok_or("missing parent directory")?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|e| format!("persist {}: {e}", parent.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove {}: {error}", path.display())),
    }
}
