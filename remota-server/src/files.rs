//! The file browser's servers (SidiOS US8 and US9): FTP/FTPS (`ftp.rs`) and SFTP over SSH. Both
//! answer the same commands and stream transfers the same way, so `ftp_session.rs` serves either.

use russh_sftp::client::{error::Error as SftpError, fs::File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    ftp::{self, check_path, sort_entries, Entry, FtpFail},
    ssh::Sftp,
};

pub enum Files {
    Ftp(ftp::Client),
    Sftp(Sftp),
}

/// A download in progress.
pub enum Reader {
    Ftp(ftp::Transfer),
    Sftp(Box<File>),
}

/// An upload in progress.
pub enum Writer {
    Ftp(ftp::Transfer),
    Sftp(Box<File>),
}

/// An SFTP failure as the user sees it: the server's status and message, one line.
fn sftp_fail(error: SftpError) -> FtpFail {
    match error {
        SftpError::Status(status) => {
            let message: String = format!("{:?}: {}", status.status_code, status.error_message)
                .chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect();
            FtpFail::Server(message)
        }
        SftpError::IO(_) | SftpError::Timeout => FtpFail::Closed,
        _ => FtpFail::Server(String::new()),
    }
}

impl Files {
    /// The folder the browser opens first.
    pub async fn start(&mut self) -> String {
        match self {
            Self::Ftp(client) => client.start.clone(),
            Self::Sftp(sftp) => sftp
                .session
                .canonicalize(".")
                .await
                .unwrap_or_else(|_| "/".to_owned()),
        }
    }

    pub async fn list(&mut self, path: &str) -> Result<(String, Vec<Entry>), FtpFail> {
        match self {
            Self::Ftp(client) => client.list(path).await,
            Self::Sftp(sftp) => {
                let path = check_path(path)?;
                let here = sftp.session.canonicalize(path).await.map_err(sftp_fail)?;
                let mut entries: Vec<Entry> = sftp
                    .session
                    .read_dir(here.clone())
                    .await
                    .map_err(sftp_fail)?
                    .filter(|entry| !matches!(entry.file_name().as_str(), "" | "." | ".."))
                    .map(|entry| {
                        let metadata = entry.metadata();
                        let kind = if metadata.is_dir() {
                            "dir"
                        } else if metadata.is_symlink() {
                            "link"
                        } else {
                            "file"
                        };
                        Entry {
                            name: entry.file_name(),
                            kind,
                            size: metadata.size.unwrap_or(0),
                            modified: metadata
                                .mtime
                                .filter(|seconds| *seconds > 0)
                                .map(|seconds| u64::from(seconds) * 1000),
                        }
                    })
                    .collect();
                sort_entries(&mut entries);
                Ok((here, entries))
            }
        }
    }

    pub async fn mkdir(&mut self, path: &str) -> Result<(), FtpFail> {
        match self {
            Self::Ftp(client) => client.mkdir(path).await,
            Self::Sftp(sftp) => sftp
                .session
                .create_dir(check_path(path)?)
                .await
                .map_err(sftp_fail),
        }
    }

    pub async fn rename(&mut self, from: &str, to: &str) -> Result<(), FtpFail> {
        match self {
            Self::Ftp(client) => client.rename(from, to).await,
            Self::Sftp(sftp) => sftp
                .session
                .rename(check_path(from)?, check_path(to)?)
                .await
                .map_err(sftp_fail),
        }
    }

    pub async fn delete(&mut self, path: &str, folder: bool) -> Result<(), FtpFail> {
        match self {
            Self::Ftp(client) => client.delete(path, folder).await,
            Self::Sftp(sftp) => {
                let path = check_path(path)?;
                if folder {
                    sftp.session.remove_dir(path).await
                } else {
                    sftp.session.remove_file(path).await
                }
                .map_err(sftp_fail)
            }
        }
    }

    pub async fn size(&mut self, path: &str) -> Option<u64> {
        match self {
            Self::Ftp(client) => client.size(path).await,
            Self::Sftp(sftp) => {
                sftp.session
                    .metadata(check_path(path).ok()?)
                    .await
                    .ok()?
                    .size
            }
        }
    }

    pub async fn download(&mut self, path: &str) -> Result<Reader, FtpFail> {
        match self {
            Self::Ftp(client) => client.download(path).await.map(Reader::Ftp),
            Self::Sftp(sftp) => sftp
                .session
                .open(check_path(path)?)
                .await
                .map(|file| Reader::Sftp(Box::new(file)))
                .map_err(sftp_fail),
        }
    }

    pub async fn upload(&mut self, path: &str) -> Result<Writer, FtpFail> {
        match self {
            Self::Ftp(client) => client.upload(path).await.map(Writer::Ftp),
            Self::Sftp(sftp) => sftp
                .session
                .create(check_path(path)?)
                .await
                .map(|file| Writer::Sftp(Box::new(file)))
                .map_err(sftp_fail),
        }
    }

    pub async fn keep_alive(&mut self) -> Result<(), FtpFail> {
        match self {
            Self::Ftp(client) => client.keep_alive().await,
            Self::Sftp(sftp) => sftp
                .session
                .canonicalize(".")
                .await
                .map(|_| ())
                .map_err(sftp_fail),
        }
    }

    pub async fn quit(self) {
        match self {
            Self::Ftp(client) => client.quit().await,
            Self::Sftp(sftp) => {
                let _ = sftp.session.close().await;
            }
        }
    }
}

impl Reader {
    pub async fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Ftp(transfer) => transfer.read(buffer).await,
            Self::Sftp(file) => file.read(buffer).await,
        }
    }

    /// Ends the transfer; for FTP, reads the server's completion reply.
    pub async fn finish(self) -> Result<(), FtpFail> {
        match self {
            Self::Ftp(transfer) => ftp::finish(transfer).await,
            Self::Sftp(file) => file.close().await.map_err(|_| FtpFail::Closed),
        }
    }
}

impl Writer {
    pub async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Ftp(transfer) => transfer.write_all(bytes).await,
            Self::Sftp(file) => file.write_all(bytes).await,
        }
    }

    /// Ends the transfer once every byte is written; the server confirms the file.
    pub async fn finish(self) -> Result<(), FtpFail> {
        match self {
            Self::Ftp(mut transfer) => {
                let _ = transfer.flush().await;
                ftp::finish(transfer).await
            }
            Self::Sftp(mut file) => {
                file.flush().await.map_err(|_| FtpFail::Closed)?;
                file.close().await.map_err(|_| FtpFail::Closed)
            }
        }
    }
}
