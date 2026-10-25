use std::{
    fs::OpenOptions,
    io::{self, Read},
    path::Path,
};

/// Read a UTF-8 regular file through a no-follow handle and enforce its size from that handle.
pub fn read_bounded_text(path: &Path, limit: u64) -> io::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }

    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(invalid_file());
    }

    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid_file());
    }
    String::from_utf8(bytes).map_err(|_| invalid_file())
}

fn invalid_file() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "file is not a bounded regular UTF-8 file",
    )
}

#[cfg(test)]
mod tests {
    use super::read_bounded_text;
    use std::{fs, io::ErrorKind};

    #[test]
    fn reads_regular_file_within_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.txt");
        fs::write(&path, "bounded text").unwrap();

        assert_eq!(read_bounded_text(&path, 12).unwrap(), "bounded text");
    }

    #[test]
    fn rejects_oversized_files_from_the_open_handle() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.txt");
        fs::write(&path, "too large").unwrap();

        assert_eq!(
            read_bounded_text(&path, 4).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_targets() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.txt");
        let link = directory.path().join("link.txt");
        fs::write(&target, "text").unwrap();
        symlink(&target, &link).unwrap();

        assert!(read_bounded_text(&link, 16).is_err());
    }
}
