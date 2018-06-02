use super::*;
use cipher;
use negotiation::Select;
use msg;
use negotiation;
use std::sync::Arc;
use std::time::Instant;
use tcp::Tcp;
use ssh_read::SshRead;
use tokio_timer::{Timer, Delay};

#[doc(hidden)]
pub enum ConnectionState<R: AsyncRead + AsyncWrite + Tcp, H: Handler> {
    ReadSshId(SshRead<R>),
    WriteSshId(WriteAll<R, CryptoVec>),
    Read(cipher::CipherRead<SshRead<R>>),
    Write(WriteAll<SshRead<R>, CryptoVec>),
    Flush(Flush<SshRead<R>>),
    Pending {
        pending: PendingFuture<H>,
        stream: SshRead<R>,
    },
    Shutdown {
        read: tokio_io::io::Read<SshRead<R>, CryptoVec>,
        read_buffer: SSHBuffer,
    },
}

#[doc(hidden)]
pub enum PendingFuture<H: Handler> {
    Ok { handler: H, session: Session },
    RejectTimeout {
        handler: H,
        session: Session,
        timeout: Delay,
    },
    ReadAuthRequest {
        session: Session,
        auth_request: encrypted::ReadAuthRequest<H>,
    },
    Authenticated(encrypted::Authenticated<H>),
}

#[doc(hidden)]
pub struct Connection<R: AsyncRead + AsyncWrite + Tcp, H: Handler> {
    pub read_buffer: Option<SSHBuffer>,
    pub session: Option<Session>,
    pub state: Option<ConnectionState<R, H>>,
    pub buffer: CryptoVec,
    pub buffer2: CryptoVec,
    pub handler: Option<H>,
    pub timeout: Option<Delay>,
}

impl<R: AsyncRead + AsyncWrite + Tcp, H: Handler> Future for Connection<R, H> {
    type Item = ();
    type Error = HandlerError<H::Error>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            // If timeout, shutdown the socket.
            if let Some(ref mut timeout) = self.timeout {
                match try!(timeout.poll()) {
                    Async::Ready(()) => {
                        // try_nb!(self.stream.get_mut().shutdown(std::net::Shutdown::Both));
                        debug!("Disconnected, shutdown");
                        return Ok(Async::Ready(()));
                    }
                    Async::NotReady => {}
                }
            }
            debug!("polling");
            if let Status::Disconnect = try_ready!(self.atomic_poll()) {
                debug!("disconnect, {}", line!());
                return Ok(Async::Ready(()));
            }
        }
    }
}

impl<R: AsyncRead + AsyncWrite + Tcp, H: Handler> AtomicPoll<HandlerError<H::Error>>
    for Connection<R, H> {
    fn atomic_poll(&mut self) -> Poll<Status, HandlerError<H::Error>> {

        match self.state.take() {
            None => {
                debug!("no state");
                Ok(Async::Ready(Status::Disconnect))
            },
            Some(ConnectionState::WriteSshId(mut write)) => {
                if let Async::Ready((stream, mut buf)) = write.poll()? {
                    // Here we're recycling the buffer used for the
                    // SSH-identification as the write buffer.
                    if let Some(ref mut session) = self.session {
                        buf.clear();
                        session.0.write_buffer.buffer = buf;
                    }
                    self.state = Some(ConnectionState::ReadSshId(SshRead::new(stream)));
                    Ok(Async::Ready(Status::Ok))
                } else {
                    Ok(Async::NotReady)
                }
            }
            Some(ConnectionState::ReadSshId(mut read)) => {
                let is_ready = if let Async::Ready(sshid) = read.read_ssh_id()? {
                    self.read_ssh_id(sshid)?;
                    true
                } else {
                    false
                };
                debug!("SSH- read: {:?}", is_ready);
                if is_ready {
                    if let Some(ref mut session) = self.session {
                        session.flush()?;
                        self.state = Some(ConnectionState::Write(
                            session.0.write_buffer.write_all(read),
                        ));
                    }
                    Ok(Async::Ready(Status::Ok))
                } else {
                    self.state = Some(ConnectionState::ReadSshId(read));
                    return Ok(Async::NotReady);
                }
            }
            Some(ConnectionState::Pending { pending, stream }) => {
                debug!("atomic pending");
                self.poll_pending(pending, stream)
            }
            Some(ConnectionState::Write(mut write)) => {
                debug!("atomic writing");
                if let Async::Ready((stream, mut buf)) = write.poll()? {
                    if let Some(ref mut session) = self.session {
                        buf.clear();
                        session.0.write_buffer.buffer = buf;
                        self.state = Some(ConnectionState::Flush(flush(stream)));
                        Ok(Async::Ready(Status::Ok))
                    } else {
                        unreachable!()
                    }
                } else {
                    self.state = Some(ConnectionState::Write(write));
                    Ok(Async::NotReady)
                }
            }
            Some(ConnectionState::Flush(mut flush)) => {
                debug!("atomic flushing");
                if let Async::Ready(mut stream) = flush.poll()? {

                    if let Some(ref mut session) = self.session {
                        if session.0.disconnected {
                            stream.tcp_shutdown()?;
                            let mut read_buffer = self.read_buffer.take().unwrap();
                            let buffer =
                                std::mem::replace(&mut read_buffer.buffer, CryptoVec::new());
                            self.state = Some(ConnectionState::Shutdown {
                                read: tokio_io::io::read(stream, buffer),
                                read_buffer,
                            });
                        } else {
                            let mut buf = self.read_buffer.take().unwrap();
                            buf.buffer.clear();
                            self.state = Some(ConnectionState::Read(
                                cipher::read(stream, buf, session.0.cipher.clone()),
                            ));
                        }
                    }
                    Ok(Async::Ready(Status::Ok))
                } else {
                    self.state = Some(ConnectionState::Flush(flush));
                    Ok(Async::NotReady)
                }
            }
            Some(ConnectionState::Read(mut read)) => {
                debug!("atomic reading");
                if let Async::Ready((stream, mut buf, end)) = read.poll()? {
                    debug!("buf: {:?}", buf.buffer.as_ref());
                    // Handle the transport layer.
                    if buf.buffer.len() < 5 || buf.buffer[5] == msg::DISCONNECT {
                        // transport
                        let buffer = std::mem::replace(&mut buf.buffer, CryptoVec::new());
                        debug!("disconnect {}", line!());
                        self.state = Some(ConnectionState::Shutdown {
                            read: tokio_io::io::read(stream, buffer),
                            read_buffer: buf,
                        });
                        return Ok(Async::Ready(Status::Ok));
                    } else if buf.buffer[5] <= 4 {
                        let session = self.session.as_ref().unwrap();
                        self.state = Some(ConnectionState::Read(
                            cipher::read(stream, buf, session.0.cipher.clone()),
                        ));
                        return Ok(Async::Ready(Status::Ok));
                    } else {
                        let result = self.read(&buf.buffer[5..end], stream);
                        self.read_buffer = Some(buf);
                        return result;
                    }
                } else {
                    debug!("atomic reading not ready");
                    self.state = Some(ConnectionState::Read(read));
                    Ok(Async::NotReady)
                }
            }
            Some(ConnectionState::Shutdown {
                     mut read,
                     mut read_buffer,
                 }) => {
                debug!("atomic shutdown");
                if let Async::Ready((stream, mut buf, n)) = read.poll()? {
                    if n == 0 {
                        read_buffer.buffer = buf;
                        self.read_buffer = Some(read_buffer);
                        Ok(Async::Ready(Status::Disconnect))
                    } else {
                        buf.clear();
                        self.state = Some(ConnectionState::Shutdown {
                            read: tokio_io::io::read(stream, buf),
                            read_buffer,
                        });
                        Ok(Async::Ready(Status::Ok))
                    }
                } else {
                    self.state = Some(ConnectionState::Shutdown { read, read_buffer });
                    Ok(Async::NotReady)
                }
            }
        }
    }
}


impl<H: Handler, R: AsyncRead + AsyncWrite + Tcp> Connection<R, H> {
    #[doc(hidden)]
    pub fn new(config: Arc<Config>, stream: R, handler: H) -> Result<Self, Error> {
        let mut write_buffer = SSHBuffer::new();
        write_buffer.send_ssh_id(config.as_ref().server_id.as_bytes());
        let timeout = if let Some(t) = config.connection_timeout {
            Some(Delay::new(Instant::now() + t))
        } else {
            None
        };
        let write = write_buffer.write_all(stream);
        let session = Session(CommonSession {
            write_buffer: SSHBuffer::new(),
            kex: None,
            auth_user: String::new(),
            auth_method: None, // Client only.
            cipher: Arc::new(cipher::CLEAR_PAIR),
            encrypted: None,
            config: config,
            wants_reply: false,
            disconnected: false,
            buffer: Some(CryptoVec::new()),
        });
        let connection = Connection {
            read_buffer: Some(SSHBuffer::new()),
            timeout: timeout,
            session: Some(session),
            state: Some(ConnectionState::WriteSshId(write)),
            handler: Some(handler),
            buffer: CryptoVec::new(),
            buffer2: CryptoVec::new(),
        };
        Ok(connection)
    }

    #[doc(hidden)]
    pub fn read_ssh_id(&mut self, sshid: &[u8]) -> Result<(), Error> {
        let mut exchange = Exchange::new();
        exchange.client_id.extend(sshid);
        // Preparing the response
        if let Some(ref mut session) = self.session {
            exchange.server_id.extend(
                session
                    .0
                    .config
                    .as_ref()
                    .server_id
                    .as_bytes(),
            );
            let mut kexinit = KexInit {
                exchange: exchange,
                algo: None,
                sent: false,
                session_id: None,
            };
            kexinit.server_write(
                session.0.config.as_ref(),
                session.0.cipher.as_ref(),
                &mut session.0.write_buffer,
            )?;
            session.0.kex = Some(Kex::KexInit(kexinit));
        }
        Ok(())
    }

    fn poll_pending(
        &mut self,
        pending: PendingFuture<H>,
        stream: SshRead<R>,
    ) -> Poll<Status, HandlerError<H::Error>> {
        debug!("Running encrypted future");
        let (handler, mut session) = match pending {
            PendingFuture::Ok { handler, session } => (handler, session),
            PendingFuture::RejectTimeout {
                handler,
                mut timeout,
                session,
            } => {
                debug!("future: rejectTimeout");
                match try!(timeout.poll()) {
                    Async::Ready(()) => (handler, session),
                    Async::NotReady => {
                        self.state = Some(ConnectionState::Pending {
                            pending: PendingFuture::RejectTimeout {
                                session,
                                timeout,
                                handler,
                            },
                            stream,
                        });
                        return Ok(Async::NotReady);
                    }
                }
            }
            PendingFuture::ReadAuthRequest {
                mut session,
                mut auth_request,
            } => {
                debug!("future: read_auth_request");
                let pre_auth = std::time::Instant::now();

                let auth = {
                    let enc = session.0.encrypted.as_mut().unwrap();
                    auth_request.poll(
                        enc,
                        &mut session.0.auth_user,
                        &mut self.buffer,
                    )?
                };

                match auth {
                    Async::Ready((handler, Auth::Reject)) => {
                        debug!("reject");
                        let rejection_time = session.0.config.auth_rejection_time;
                        let timer = Timer::default();
                        let now = std::time::Instant::now();
                        self.state = Some(ConnectionState::Pending {
                            pending: PendingFuture::RejectTimeout {
                                session,
                                handler,
                                timeout: Delay::new(pre_auth + rejection_time)
                            },
                            stream,
                        });
                        return Ok(Async::Ready(Status::Ok));
                    }
                    Async::Ready((handler, _)) => (handler, session),
                    Async::NotReady => {
                        self.state = Some(ConnectionState::Pending {
                            pending: PendingFuture::ReadAuthRequest {
                                session,
                                auth_request,
                            },
                            stream,
                        });
                        return Ok(Async::NotReady);
                    }
                }
            }
            PendingFuture::Authenticated(mut r) => {
                debug!("future: authenticated");
                if let Async::Ready((handler, session)) = try!(r.poll()) {
                    (handler, session)
                } else {
                    self.state = Some(ConnectionState::Pending {
                        pending: PendingFuture::Authenticated(r),
                        stream,
                    });
                    return Ok(Async::NotReady);
                }
            }
        };


        self.handler = Some(handler);
        session.flush()?;
        self.state = Some(ConnectionState::Write(
            session.0.write_buffer.write_all(stream),
        ));
        self.session = Some(session);
        Ok(Async::Ready(Status::Ok))
    }


    fn read(
        &mut self,
        buf: &[u8],
        stream: SshRead<R>,
    ) -> Poll<Status, HandlerError<<H as Handler>::Error>> {

        let mut session = self.session.take().unwrap();

        // Handle key exchange/re-exchange.
        match session.0.kex.take() {
            Some(Kex::KexInit(kexinit)) => {
                if kexinit.algo.is_some() || buf[0] == msg::KEXINIT ||
                    session.0.encrypted.is_none()
                {
                    let next_kex = kexinit.server_parse(
                        session.0.config.as_ref(),
                        &session.0.cipher,
                        &buf,
                        &mut session.0.write_buffer,
                    );
                    match next_kex {
                        Ok(next_kex) => {
                            session.0.kex = Some(next_kex);
                            session.flush()?;
                            self.state = Some(ConnectionState::Write(
                                session.0.write_buffer.write_all(stream),
                            ));
                            self.session = Some(session);
                            return Ok(Async::Ready(Status::Ok));
                        }
                        Err(e) => {
                            session.flush()?;
                            self.state = Some(ConnectionState::Write(
                                session.0.write_buffer.write_all(stream),
                            ));
                            self.session = Some(session);
                            return Err(HandlerError::Error(e));
                        }
                    }
                }
                // Else, i.e. if the other side has not started
                // the key exchange, process its packets by simple
                // not returning.
            }
            Some(Kex::KexDh(kexdh)) => {
                let next_kex = kexdh.parse(
                    session.0.config.as_ref(),
                    &mut self.buffer,
                    &mut self.buffer2,
                    &session.0.cipher,
                    &buf,
                    &mut session.0.write_buffer,
                );
                match next_kex {
                    Ok(next_kex) => {
                        session.0.kex = Some(next_kex);
                        session.flush()?;
                        self.state = Some(ConnectionState::Write(
                            session.0.write_buffer.write_all(stream),
                        ));
                        self.session = Some(session);
                        return Ok(Async::Ready(Status::Ok));
                    }
                    Err(e) => {
                        session.flush()?;
                        self.state = Some(ConnectionState::Write(
                            session.0.write_buffer.write_all(stream),
                        ));
                        self.session = Some(session);
                        return Err(HandlerError::Error(e));
                    }
                }
            }
            Some(Kex::NewKeys(newkeys)) => {
                if buf[0] != msg::NEWKEYS {
                    session.flush()?;
                    self.state = Some(ConnectionState::Write(
                        session.0.write_buffer.write_all(stream),
                    ));
                    self.session = Some(session);
                    return Err(HandlerError::Error(Error::Kex));
                }
                // Ok, NEWKEYS received, now encrypted.
                session.0.encrypted(
                    EncryptedState::WaitingServiceRequest,
                    newkeys,
                );
                session.flush()?;
                self.state = Some(ConnectionState::Write(
                    session.0.write_buffer.write_all(stream),
                ));
                self.session = Some(session);
                return Ok(Async::Ready(Status::Ok));
            }
            Some(kex) => {
                session.0.kex = Some(kex);
                session.flush()?;
                self.state = Some(ConnectionState::Write(
                    session.0.write_buffer.write_all(stream),
                ));
                self.session = Some(session);
                return Ok(Async::Ready(Status::Ok));
            }
            None => {}
        }

        // Start a key re-exchange, if the client is asking for it.
        if buf[0] == msg::KEXINIT {
            // Now, if we're encrypted:
            if let Some(ref mut enc) = session.0.encrypted {

                // If we're not currently rekeying, but buf is a rekey request
                if let Some(exchange) = enc.exchange.take() {
                    let pref = &session.0.config.as_ref().preferred;
                    let kexinit = KexInit::received_rekey(
                        exchange,
                        negotiation::Server::read_kex(buf, pref)?,
                        &enc.session_id,
                    );
                    session.0.kex = Some(kexinit.server_parse(
                        session.0.config.as_ref(),
                        &mut session.0.cipher,
                        buf,
                        &mut session.0.write_buffer,
                    )?);
                }
            }
            session.flush()?;
            self.state = Some(ConnectionState::Write(
                session.0.write_buffer.write_all(stream),
            ));
            self.session = Some(session);
            return Ok(Async::Ready(Status::Ok));
        }

        // No kex going on, and the version id is done.
        self.state = Some(ConnectionState::Pending {
            pending: session.server_read_encrypted(
                self.handler.take().unwrap(),
                &buf,
            )?,
            stream,
        });
        Ok(Async::Ready(Status::Ok))
    }
}
