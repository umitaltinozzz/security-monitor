use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use flate2::read::GzDecoder;
use security_monitor_advisory_providers::{ProviderError, PublicDataHttp};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use tokio::{fs::File as AsyncFile, io::AsyncWriteExt};
use zip::ZipArchive;

use crate::{
    types::{EngineKind, ScannerError},
    version::{self, DownloadArtifact},
};

const MAX_EXTRACTED_BINARY_BYTES: u64 = 100 * 1024 * 1024;

pub struct ScannerAdapters {
    pub(crate) http: PublicDataHttp,
    pub(crate) app_data_dir: PathBuf,
}

impl ScannerAdapters {
    pub fn new(http: PublicDataHttp, app_data_dir: impl Into<PathBuf>) -> Self {
        Self {
            http,
            app_data_dir: app_data_dir.into(),
        }
    }

    pub async fn install_pinned(
        &self,
        engine: EngineKind,
        user_approved_download: bool,
    ) -> Result<PathBuf, ScannerError> {
        if !user_approved_download {
            return Err(ScannerError::DownloadNotApproved);
        }
        let platform = version::platform_key().ok_or(ScannerError::UnsupportedPlatform)?;
        let Some(tool) = version::pinned_tool(engine)? else {
            return Err(ScannerError::UnsupportedPlatform);
        };
        let Some(artifact) = tool.downloads.get(&platform) else {
            return Err(ScannerError::UnsupportedPlatform);
        };
        validate_artifact(artifact)?;

        let (root, install_directory) = self.install_directory(engine, &tool.version)?;
        let target = install_directory.join(&artifact.binary);
        let marker = install_directory.join("integrity.txt");
        if target.exists() || fs::symlink_metadata(&target).is_ok() {
            if fs::symlink_metadata(&target)
                .map_err(ScannerError::Io)?
                .file_type()
                .is_symlink()
            {
                return Err(ScannerError::UnsafePath);
            }
            let canonical_target = target.canonicalize().map_err(ScannerError::Io)?;
            if !canonical_target.starts_with(&root) {
                return Err(ScannerError::UnsafePath);
            }
            if is_verified_install(
                &canonical_target,
                &install_directory,
                &marker,
                &artifact.sha256,
            )
            .await?
            {
                return Ok(canonical_target);
            }
            return Err(ScannerError::DestinationOccupied);
        }

        let archive = NamedTempFile::new_in(&install_directory).map_err(ScannerError::Io)?;
        let archive_path = archive.path().to_path_buf();
        let mut async_archive = AsyncFile::from_std(archive.reopen().map_err(ScannerError::Io)?);
        self.http
            .download_to_writer(&artifact.url, &mut async_archive, tool.max_download_bytes)
            .await
            .map_err(map_download_error)?;
        async_archive.flush().await.map_err(ScannerError::Io)?;
        async_archive.sync_all().await.map_err(ScannerError::Io)?;
        drop(async_archive);
        verify_checksum(&archive_path, &artifact.sha256).await?;

        let binary = if artifact.format == "raw" {
            archive
        } else {
            let mut binary = NamedTempFile::new_in(&install_directory).map_err(ScannerError::Io)?;
            let source_path = archive_path;
            let binary_name = artifact.binary.clone();
            let archive_format = artifact.format.clone();
            tokio::task::spawn_blocking(move || {
                extract_binary(
                    &source_path,
                    &binary_name,
                    &archive_format,
                    MAX_EXTRACTED_BINARY_BYTES,
                    binary.as_file_mut(),
                )?;
                binary.as_file_mut().flush().map_err(ScannerError::Io)?;
                binary.as_file().sync_all().map_err(ScannerError::Io)?;
                Ok::<_, ScannerError>(binary)
            })
            .await
            .map_err(|_| ScannerError::InvalidArchive)??
        };
        set_executable_permissions(binary.path())?;
        let binary_hash = hash_file(binary.path()).await?;
        binary
            .persist_noclobber(&target)
            .map_err(|error| ScannerError::Io(error.error))?;
        let target = target.canonicalize().map_err(ScannerError::Io)?;
        if !target.starts_with(&root) {
            let _ = fs::remove_file(&target);
            return Err(ScannerError::UnsafePath);
        }
        if let Err(error) = write_integrity_marker(&marker, &artifact.sha256, &binary_hash) {
            let _ = fs::remove_file(&target);
            return Err(error);
        }
        Ok(target)
    }

    fn install_directory(
        &self,
        engine: EngineKind,
        version: &str,
    ) -> Result<(PathBuf, PathBuf), ScannerError> {
        fs::create_dir_all(&self.app_data_dir).map_err(ScannerError::Io)?;
        let root = self.app_data_dir.canonicalize().map_err(ScannerError::Io)?;
        let scanners = root.join("scanners");
        fs::create_dir_all(&scanners).map_err(ScannerError::Io)?;
        let scanners = scanners.canonicalize().map_err(ScannerError::Io)?;
        if !scanners.starts_with(&root) {
            return Err(ScannerError::UnsafePath);
        }
        let engine_directory = scanners.join(engine.as_str());
        fs::create_dir_all(&engine_directory).map_err(ScannerError::Io)?;
        let engine_directory = engine_directory.canonicalize().map_err(ScannerError::Io)?;
        if !engine_directory.starts_with(&scanners) {
            return Err(ScannerError::UnsafePath);
        }
        let install_directory = engine_directory.join(version);
        fs::create_dir_all(&install_directory).map_err(ScannerError::Io)?;
        let install_directory = install_directory.canonicalize().map_err(ScannerError::Io)?;
        if !install_directory.starts_with(&engine_directory) {
            return Err(ScannerError::UnsafePath);
        }
        Ok((root, install_directory))
    }
}

fn validate_artifact(artifact: &DownloadArtifact) -> Result<(), ScannerError> {
    let url = url::Url::parse(&artifact.url).map_err(|_| ScannerError::VersionConfiguration)?;
    let pinned_release_path = url.host_str() == Some("github.com")
        && (url
            .path()
            .starts_with("/google/osv-scanner/releases/download/")
            || url
                .path()
                .starts_with("/aquasecurity/trivy/releases/download/"));
    if url.scheme() != "https"
        || !pinned_release_path
        || artifact.sha256.len() != 64
        || !artifact
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ScannerError::VersionConfiguration);
    }
    if !matches!(artifact.format.as_str(), "raw" | "tar_gz" | "zip")
        || artifact.binary.is_empty()
        || Path::new(&artifact.binary).components().count() != 1
        || !Path::new(&artifact.binary)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ScannerError::VersionConfiguration);
    }
    Ok(())
}

async fn hash_file(path: &Path) -> Result<String, ScannerError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut file = File::open(path).map_err(ScannerError::Io)?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 32 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(ScannerError::Io)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        Ok(format!("{:x}", digest.finalize()))
    })
    .await
    .map_err(|_| ScannerError::Io(std::io::Error::other("checksum task failed")))?
}

async fn verify_checksum(path: &Path, expected: &str) -> Result<(), ScannerError> {
    if hash_file(path).await? == expected {
        Ok(())
    } else {
        Err(ScannerError::ChecksumMismatch)
    }
}

fn extract_binary(
    archive_path: &Path,
    expected_name: &str,
    format: &str,
    max_bytes: u64,
    output: &mut File,
) -> Result<(), ScannerError> {
    match format {
        "tar_gz" => extract_tar_gz(archive_path, expected_name, max_bytes, output),
        "zip" => extract_zip(archive_path, expected_name, max_bytes, output),
        _ => Err(ScannerError::InvalidArchive),
    }
}

fn extract_tar_gz(
    archive_path: &Path,
    expected_name: &str,
    max_bytes: u64,
    output: &mut File,
) -> Result<(), ScannerError> {
    let file = File::open(archive_path).map_err(ScannerError::Io)?;
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    let mut found = false;
    for entry in archive
        .entries()
        .map_err(|_| ScannerError::InvalidArchive)?
    {
        let entry = entry.map_err(|_| ScannerError::InvalidArchive)?;
        let path = entry.path().map_err(|_| ScannerError::InvalidArchive)?;
        validate_archive_path(&path)?;
        if path != Path::new(expected_name) {
            continue;
        }
        if found || !entry.header().entry_type().is_file() {
            return Err(ScannerError::InvalidArchive);
        }
        found = true;
        if entry.size() > max_bytes {
            return Err(ScannerError::InvalidArchive);
        }
        let copied = std::io::copy(&mut entry.take(max_bytes.saturating_add(1)), output)
            .map_err(ScannerError::Io)?;
        if copied == 0 || copied > max_bytes {
            return Err(ScannerError::InvalidArchive);
        }
    }
    if found {
        Ok(())
    } else {
        Err(ScannerError::InvalidArchive)
    }
}

fn extract_zip(
    archive_path: &Path,
    expected_name: &str,
    max_bytes: u64,
    output: &mut File,
) -> Result<(), ScannerError> {
    let file = File::open(archive_path).map_err(ScannerError::Io)?;
    let mut archive = ZipArchive::new(file).map_err(|_| ScannerError::InvalidArchive)?;
    let mut found = false;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|_| ScannerError::InvalidArchive)?;
        let path = entry
            .enclosed_name()
            .ok_or(ScannerError::InvalidArchive)?
            .to_path_buf();
        validate_archive_path(&path)?;
        if path != Path::new(expected_name) {
            continue;
        }
        let mode = entry.unix_mode().unwrap_or(0);
        if found || mode & 0o170000 == 0o120000 || entry.is_dir() {
            return Err(ScannerError::InvalidArchive);
        }
        found = true;
        if entry.size() > max_bytes {
            return Err(ScannerError::InvalidArchive);
        }
        let copied = std::io::copy(&mut entry.take(max_bytes.saturating_add(1)), output)
            .map_err(ScannerError::Io)?;
        if copied == 0 || copied > max_bytes {
            return Err(ScannerError::InvalidArchive);
        }
    }
    if found {
        Ok(())
    } else {
        Err(ScannerError::InvalidArchive)
    }
}

fn validate_archive_path(path: &Path) -> Result<(), ScannerError> {
    if path
        .components()
        .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
    {
        Ok(())
    } else {
        Err(ScannerError::InvalidArchive)
    }
}

#[cfg(unix)]
fn set_executable_permissions(path: &Path) -> Result<(), ScannerError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(ScannerError::Io)
}

#[cfg(not(unix))]
fn set_executable_permissions(_path: &Path) -> Result<(), ScannerError> {
    Ok(())
}

fn write_integrity_marker(
    path: &Path,
    asset_sha256: &str,
    binary_sha256: &str,
) -> Result<(), ScannerError> {
    let mut temporary = NamedTempFile::new_in(path.parent().ok_or(ScannerError::UnsafePath)?)
        .map_err(ScannerError::Io)?;
    writeln!(temporary, "{asset_sha256}\n{binary_sha256}").map_err(ScannerError::Io)?;
    temporary.as_file().sync_all().map_err(ScannerError::Io)?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| ScannerError::Io(error.error))?;
    Ok(())
}

async fn is_verified_install(
    binary: &Path,
    install_directory: &Path,
    marker: &Path,
    expected_asset_hash: &str,
) -> Result<bool, ScannerError> {
    let marker = match fs::symlink_metadata(marker) {
        Ok(metadata) if metadata.file_type().is_symlink() => return Err(ScannerError::UnsafePath),
        Ok(metadata) if metadata.is_file() => marker.canonicalize().map_err(ScannerError::Io)?,
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(ScannerError::Io(error)),
    };
    let install_directory = install_directory.canonicalize().map_err(ScannerError::Io)?;
    if !marker.starts_with(&install_directory) {
        return Err(ScannerError::UnsafePath);
    }
    let contents = fs::read_to_string(marker).map_err(ScannerError::Io)?;
    let mut lines = contents.lines();
    let asset_hash = lines.next().unwrap_or_default();
    let binary_hash = lines.next().unwrap_or_default();
    if asset_hash != expected_asset_hash {
        return Ok(false);
    }
    Ok(hash_file(binary).await? == binary_hash)
}

fn map_download_error(error: ProviderError) -> ScannerError {
    if matches!(error, ProviderError::NetworkDisabled) {
        ScannerError::DownloadDisabled
    } else {
        ScannerError::Download
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, Header};
    use tempfile::tempdir;
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::{extract_binary, validate_artifact, verify_checksum, write_integrity_marker};
    use crate::version::{DownloadArtifact, versions};

    #[test]
    fn pinned_artifacts_use_https_allowlisted_urls_and_sha256_values() {
        let config = versions().unwrap();
        for artifact in config
            .osv_scanner
            .downloads
            .values()
            .chain(config.trivy.downloads.values())
        {
            validate_artifact(artifact).unwrap();
        }
    }

    #[test]
    fn tar_extractor_reads_only_the_named_binary() {
        let directory = tempdir().unwrap();
        let archive_path = directory.path().join("trivy.tar.gz");
        let compressed = File::create(&archive_path).unwrap();
        let encoder = GzEncoder::new(compressed, Compression::fast());
        let mut archive = Builder::new(encoder);
        let bytes = b"pinned test binary";
        let mut header = Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        archive
            .append_data(&mut header, "trivy", bytes.as_slice())
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap();

        let mut output = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        extract_binary(&archive_path, "trivy", "tar_gz", 100, output.as_file_mut()).unwrap();
        output.as_file_mut().flush().unwrap();
        assert_eq!(std::fs::read(output.path()).unwrap(), bytes);
    }

    #[test]
    fn zip_extractor_rejects_path_traversal_entries() {
        let directory = tempdir().unwrap();
        let archive_path = directory.path().join("trivy.zip");
        let mut archive = ZipWriter::new(File::create(&archive_path).unwrap());
        archive
            .start_file("../trivy.exe", SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"bad").unwrap();
        archive.finish().unwrap();

        let mut output = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        assert!(
            extract_binary(&archive_path, "trivy.exe", "zip", 100, output.as_file_mut(),).is_err()
        );
        assert!(!directory.path().join("trivy.exe").exists());
    }

    #[test]
    fn integrity_marker_records_verified_asset_and_binary_digests() {
        let directory = tempdir().unwrap();
        let marker = directory.path().join("integrity.txt");
        write_integrity_marker(&marker, &"a".repeat(64), &"b".repeat(64)).unwrap();
        assert_eq!(
            std::fs::read_to_string(marker).unwrap(),
            format!("{}\n{}\n", "a".repeat(64), "b".repeat(64))
        );
    }

    #[test]
    fn malformed_download_manifest_hash_is_rejected() {
        let artifact = DownloadArtifact {
            url: "https://github.com/example/release/download/file".to_owned(),
            sha256: "secret".to_owned(),
            format: "raw".to_owned(),
            binary: "scanner".to_owned(),
        };
        assert!(validate_artifact(&artifact).is_err());
    }

    #[tokio::test]
    async fn downloaded_bytes_must_match_the_pinned_sha256() {
        let directory = tempdir().unwrap();
        let asset = directory.path().join("scanner.bin");
        std::fs::write(&asset, b"hello").unwrap();

        verify_checksum(
            &asset,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )
        .await
        .unwrap();
        assert!(verify_checksum(&asset, &"0".repeat(64)).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn integrity_marker_symlinks_are_rejected() {
        let directory = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let binary = directory.path().join("scanner");
        let marker = directory.path().join("integrity.txt");
        std::fs::write(&binary, b"scanner").unwrap();
        std::fs::write(outside.path().join("integrity.txt"), "a\nb\n").unwrap();
        std::os::unix::fs::symlink(outside.path().join("integrity.txt"), &marker).unwrap();

        let error = super::is_verified_install(&binary, directory.path(), &marker, &"a".repeat(64))
            .await
            .unwrap_err();

        assert!(matches!(error, crate::ScannerError::UnsafePath));
    }
}
