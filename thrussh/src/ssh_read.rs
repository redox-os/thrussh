use std;
use Error;
use cryptovec::CryptoVec;
use futures::{Async, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tcp::Tcp;
use std::io::ErrorKind;

/// The buffer to read the identification string (first line in the
/// protocol).
struct ReadSshIdBuffer {
    pub buf: CryptoVec,
    pub total: usize,
    pub bytes_read: usize,
    pub sshid_len: usize,
}

impl ReadSshIdBuffer {
    pub fn id(&self) -> &[u8] {
        &self.buf[..self.sshid_len]
    }

    pub fn new() -> ReadSshIdBuffer {
        let mut buf = CryptoVec::new();
        buf.resize(256);
        ReadSshIdBuffer {
            buf: buf,
            sshid_len: 0,
            bytes_read: 0,
            total: 0,
        }
    }
}

impl std::fmt::Debug for ReadSshIdBuffer {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "ReadSshId {:?}", self.id())
    }
}

/// SshRead<R> is the same as R, plus a small buffer in the beginning to
/// read the identification string. After the first line in the
/// connection, the `id` parameter is never used again.
pub struct SshRead<R> {
    id: Option<ReadSshIdBuffer>,
    r: R,
}

impl<R: std::io::Read> std::io::Read for SshRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        if let Some(mut id) = self.id.take() {
            debug!("id {:?} {:?}", id.total, id.bytes_read);
            if id.total > id.bytes_read {
                let result = {
                    let mut readable = &id.buf[id.bytes_read..id.total];
                    readable.read(buf).unwrap()
                };
                debug!("read {:?} bytes from id.buf", result);
                id.bytes_read += result;
                self.id = Some(id);
                return Ok(result);
            }
        }
        self.r.read(buf)
    }
}

impl<R: AsyncRead> AsyncRead for SshRead<R> {}

impl<R: std::io::Write> std::io::Write for SshRead<R> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.r.write(buf)
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.r.flush()
    }
}

impl<R: AsyncWrite> AsyncWrite for SshRead<R> {
    fn shutdown(&mut self) -> Poll<(), std::io::Error> {
        self.r.shutdown()
    }
}


impl<R: Tcp> Tcp for SshRead<R> {
    fn tcp_shutdown(&mut self) -> Result<(), std::io::Error> {
        self.r.tcp_shutdown()
    }
}



impl<R: std::io::Read> SshRead<R> {
    pub fn new(r: R) -> Self {
        SshRead {
            id: Some(ReadSshIdBuffer::new()),
            r: r,
        }
    }

    pub fn read_ssh_id(&mut self) -> Poll<&[u8], Error> {
        let ssh_id = self.id.as_mut().unwrap();
        loop {
            let mut i = 0;
            debug!("read_ssh_id: reading");
            let n = match self.r.read(&mut ssh_id.buf[ssh_id.total..]) {
                Ok(n) => n,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => return Ok(Async::NotReady),
                Err(e) => return Err(e.into())
            };
            debug!("read {:?}", n);

            // let buf = try_nb!(stream.fill_buf());
            ssh_id.total += n;
            debug!("{:?}", std::str::from_utf8(&ssh_id.buf[..ssh_id.total]));
            if n == 0 {
                return Err(Error::Disconnect);
            }
            loop {
                if i >= ssh_id.total - 1 {
                    break;
                }
                if ssh_id.buf[i] == b'\r' && ssh_id.buf[i + 1] == b'\n' {
                    ssh_id.bytes_read = i + 2;
                    break;
                } else if ssh_id.buf[i + 1] == b'\n' {
                    // This is really wrong, but OpenSSH 7.4 uses
                    // it.
                    ssh_id.bytes_read = i + 2;
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }

            if ssh_id.bytes_read > 0 {
                // If we have a full line, handle it.
                if i >= 8 {
                    if &ssh_id.buf[0..8] == b"SSH-2.0-" {
                        // Either the line starts with "SSH-2.0-"
                        ssh_id.sshid_len = i;
                        return Ok(Async::Ready(&ssh_id.buf[..ssh_id.sshid_len]));
                    }
                }
                // Else, it is a "preliminary" (see
                // https://tools.ietf.org/html/rfc4253#section-4.2),
                // and we can discard it and read the next one.
                ssh_id.total = 0;
                ssh_id.bytes_read = 0;
            }
            debug!("bytes_read: {:?}", ssh_id.bytes_read);
        }
    }
}
