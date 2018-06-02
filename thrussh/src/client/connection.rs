use super::*;
use cipher;
use msg;
use thrussh_keys::encoding::Reader;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use ssh_read::SshRead;
use tcp::Tcp;
use tokio_io;
use tokio_timer::Delay;

#[doc(hidden)]
pub enum ConnectionState<R: AsyncRead + AsyncWrite, H: Handler> {
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
    ServerKeyCheck {
        check: H::FutureBool,
        kexdhdone: KexDhDone,
        buf_len: usize,
        session: Session,
    },
    AgentSign {
        sign: H::FutureSign,
        session: Session,
        request_index: usize,
        buffer_len: usize,
    },
    SessionUnit(H::SessionUnit),
    Done(H, Session),
}

/// Client connection. A connection implements `Future`, returning
/// `()` when it finishes (for instance if the client and server agree
/// to close the connection).
pub struct Connection<R: AsyncRead + AsyncWrite, H: Handler> {
    #[doc(hidden)]
    pub read_buffer: Option<SSHBuffer>,
    #[doc(hidden)]
    /// Session of this connection.
    pub session: Option<Session>,
    #[doc(hidden)]
    pub state: Option<ConnectionState<R, H>>,
    #[doc(hidden)]
    pub buffer: CryptoVec,
    #[doc(hidden)]
    /// Handler for this connection.
    pub handler: Option<H>,
    #[doc(hidden)]
    pub timeout: Option<Delay>,
}

impl<R: AsyncRead + AsyncWrite, H: Handler> std::ops::Deref
    for Connection<R, H> {
    type Target = Session;
    fn deref(&self) -> &Self::Target {
        self.session.as_ref().unwrap()
    }
}

impl<R: AsyncRead + AsyncWrite, H: Handler> std::ops::DerefMut
    for Connection<R, H> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.session.as_mut().unwrap()
    }
}

impl<
    R: AsyncRead + AsyncWrite + Tcp,
    H: Handler,
> AtomicPoll<HandlerError<H::Error>> for Connection<R, H> {
    /// Process all packets available in the buffer, and returns
    /// whether the connection should continue.
    fn atomic_poll(&mut self) -> Poll<Status, HandlerError<H::Error>> {

        match self.state.take() {
            None => Ok(Async::Ready(Status::Disconnect)),
            Some(ConnectionState::WriteSshId(mut write)) => {
                if let Async::Ready((stream, mut buf)) = write.poll()? {
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
            Some(ConnectionState::ReadSshId(mut stream)) => {
                let is_ready = if let Async::Ready(sshid) = stream.read_ssh_id()? {
                    self.read_ssh_id(sshid)?;
                    true
                } else {
                    false
                };
                debug!("SSH- read {:?}", is_ready);
                if is_ready {
                    if let Some(ref mut session) = self.session {
                        session.flush()?;
                        self.state = Some(ConnectionState::Write(
                            session.0.write_buffer.write_all(stream),
                        ));
                    }
                    Ok(Async::Ready(Status::Ok))
                } else {
                    self.state = Some(ConnectionState::ReadSshId(stream));
                    Ok(Async::NotReady)
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

                        session.flush()?;
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
                        // Disconnect.
                        let buffer = std::mem::replace(&mut buf.buffer, CryptoVec::new());
                        self.state = Some(ConnectionState::Shutdown {
                            read: tokio_io::io::read(stream, buffer),
                            read_buffer: buf,
                        });
                        return Ok(Async::Ready(Status::Ok));
                    } else if buf.buffer[5] <= 4 {
                        let session = self.session.as_ref().unwrap();
                        buf.buffer.clear();
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


impl<R: AsyncRead + AsyncWrite, H: Handler> Connection<R, H> {
    fn poll_pending(
        &mut self,
        pending: PendingFuture<H>,
        stream: SshRead<R>,
    ) -> Poll<Status, HandlerError<H::Error>> {

        match pending {
            PendingFuture::SessionUnit(mut f) => {
                if let Async::Ready((h, mut session)) = f.poll().map_err(HandlerError::Handler)? {
                    self.handler = Some(h);
                    session.flush()?;
                    self.state = Some(ConnectionState::Write(
                        session.0.write_buffer.write_all(stream),
                    ));
                    self.session = Some(session);
                    Ok(Async::Ready(Status::Ok))
                } else {
                    self.state = Some(ConnectionState::Pending {
                        pending: PendingFuture::SessionUnit(f),
                        stream,
                    });
                    Ok(Async::NotReady)
                }
            }
            PendingFuture::Done(h, mut session) => {
                self.handler = Some(h);
                session.flush()?;
                self.state = Some(ConnectionState::Write(
                    session.0.write_buffer.write_all(stream),
                ));
                self.session = Some(session);
                Ok(Async::Ready(Status::Ok))
            }
            PendingFuture::ServerKeyCheck {
                mut check,
                kexdhdone,
                buf_len,
                mut session,
            } => {
                match check.poll().map_err(HandlerError::Handler)? {
                    Async::Ready((h, true)) => {
                        self.pending_server_key_check(
                            buf_len,
                            kexdhdone,
                            &mut session,
                        )?;
                        self.handler = Some(h);
                        session.flush()?;
                        self.state = Some(ConnectionState::Write(
                            session.0.write_buffer.write_all(stream),
                        ));
                        self.session = Some(session);
                        Ok(Async::Ready(Status::Ok))
                    }
                    Async::Ready((h, false)) => {
                        self.handler = Some(h);
                        session.flush()?;
                        self.state = Some(ConnectionState::Write(
                            session.0.write_buffer.write_all(stream),
                        ));
                        self.session = Some(session);
                        Err(HandlerError::Error(Error::UnknownKey))
                    }
                    Async::NotReady => {
                        self.state = Some(ConnectionState::Pending {
                            pending: PendingFuture::ServerKeyCheck {
                                check: check,
                                kexdhdone: kexdhdone,
                                buf_len: buf_len,
                                session,
                            },
                            stream,
                        });
                        Ok(Async::NotReady)
                    }
                }
            }
            PendingFuture::AgentSign { mut sign, mut session, request_index, buffer_len } => {
                if let Async::Ready((h, signature)) = sign.poll().map_err(HandlerError::Handler)? {

                    if signature.len() != buffer_len {
                        // The buffer was modified.
                        if let Some(ref mut enc) = session.0.encrypted {
                            push_packet!(enc.write, {
                                enc.write.extend(&signature[request_index..]);
                            })
                        }
                    } else {
                        session.0.auth_method = None;
                    }
                    session.0.buffer = Some(signature);
                    session.flush()?;
                    self.state = Some(ConnectionState::Write(
                        session.0.write_buffer.write_all(stream),
                    ));

                    self.handler = Some(h);
                    self.session = Some(session);
                    Ok(Async::Ready(Status::Ok))
                } else {
                    self.state = Some(ConnectionState::Pending {
                        pending: PendingFuture::AgentSign { sign, session, request_index, buffer_len },
                        stream,
                    });
                    Ok(Async::NotReady)
                }
            }
        }
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
                    let kexdhdone = kexinit.client_parse(
                        session.0.config.as_ref(),
                        &session.0.cipher,
                        buf,
                        &mut session.0.write_buffer,
                    );
                    match kexdhdone {
                        Ok(kexdhdone) => {
                            session.0.kex = Some(Kex::KexDhDone(kexdhdone));
                            session.flush()?;
                            debug!("calling write_all");
                            self.state = Some(ConnectionState::Write(
                                session.0.write_buffer.write_all(stream),
                            ));
                            self.session = Some(session);
                            return Ok(Async::Ready(Status::Ok));
                        }
                        Err(e) => {
                            self.session = Some(session);
                            return Err(HandlerError::Error(e));
                        }
                    }
                } else {
                    unreachable!()
                }
            }
            Some(Kex::KexDhDone(mut kexdhdone)) => {
                if kexdhdone.names.ignore_guessed {
                    kexdhdone.names.ignore_guessed = false;
                    session.0.kex = Some(Kex::KexDhDone(kexdhdone));
                    session.flush()?;
                    debug!("calling write_all");
                    self.state = Some(ConnectionState::Write(
                        session.0.write_buffer.write_all(stream),
                    ));
                    self.session = Some(session);
                    return Ok(Async::Ready(Status::Ok));
                } else {
                    // We've sent ECDH_INIT, waiting for ECDH_REPLY
                    if buf[0] == msg::KEX_ECDH_REPLY {
                        let mut reader = buf.reader(1);
                        let pubkey = reader.read_string()?; // server public key.
                        let pubkey = parse_public_key(pubkey)?;
                        self.state = Some(ConnectionState::Pending {
                            pending: PendingFuture::ServerKeyCheck {
                                check: self.handler.take().unwrap().check_server_key(&pubkey),
                                kexdhdone: kexdhdone,
                                buf_len: buf.len(),
                                session: session,
                            },
                            stream,
                        });
                        return Ok(Async::Ready(Status::Ok));
                    } else {
                        self.state = Some(ConnectionState::Write(
                            session.0.write_buffer.write_all(stream),
                        ));
                        self.session = Some(session);
                        return Err(HandlerError::Error(Error::Inconsistent));
                    }
                }
            }
            Some(Kex::NewKeys(newkeys)) => {
                if buf[0] != msg::NEWKEYS {
                    return Err(HandlerError::Error(Error::Kex));
                }
                session.0.encrypted(
                    EncryptedState::WaitingServiceRequest,
                    newkeys,
                );
                // Ok, NEWKEYS received, now encrypted.
                let p = b"\x05\0\0\0\x0Cssh-userauth";
                session.0.cipher.write(p, &mut session.0.write_buffer);
                session.flush()?;
                self.state = Some(ConnectionState::Write(
                    session.0.write_buffer.write_all(stream),
                ));
                self.session = Some(session);
                return Ok(Async::Ready(Status::Ok));
            }
            Some(kex) => {
                session.0.kex = Some(kex);
                self.state = Some(ConnectionState::Write(
                    session.0.write_buffer.write_all(stream),
                ));
                self.session = Some(session);
                return Ok(Async::Ready(Status::Ok));
            }
            None => {}
        }
        debug!("atomic poll: take 2");
        self.state = Some(ConnectionState::Pending {
            pending: session.client_read_encrypted(
                self.handler.take().unwrap(),
                &buf
            )?,
            stream,
        });
        Ok(Async::Ready(Status::Ok))
    }
}

impl<R: AsyncRead + AsyncWrite, H: Handler> Connection<R, H> {
    #[doc(hidden)]
    pub fn is_reading(&self) -> bool {
        match self.state {
            Some(ConnectionState::Read(_)) => true,
            _ => false,
        }
    }

    #[doc(hidden)]
    pub fn abort_read(&mut self) -> Result<(), Error> {
        match self.state.take() {
            Some(ConnectionState::Read(mut read)) => {
                if let Some((stream, read_buffer)) = read.try_abort() {
                    self.read_buffer = Some(read_buffer);
                    if let Some(ref mut session) = self.session {
                        session.flush()?;
                    }
                    self.state = Some(ConnectionState::Write(
                        self.session.as_mut().unwrap().0.write_buffer.write_all(
                            stream,
                        ),
                    ))
                } else {
                    self.state = Some(ConnectionState::Read(read))
                }
            }
            st => self.state = st,
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Poll<(), HandlerError<H::Error>> {
        if let Some(ref mut timeout) = self.timeout {
            if let Async::Ready(()) = timeout.poll()? {
                debug!("Timeout, shutdown");
                if let Some(ref mut s) = self.session {
                    s.0.disconnected = true;
                }
                return Err(HandlerError::Error(Error::ConnectionTimeout))
            }
        }
        Ok(Async::Ready(()))
    }

    fn pending_server_key_check(
        &mut self,
        buf_len: usize,
        mut kexdhdone: KexDhDone,
        session: &mut Session,
    ) -> Result<(), HandlerError<H::Error>> {

        let hash = {
            let buf = &self.read_buffer.as_ref().unwrap().buffer[5..5 + buf_len];
            let mut reader = buf.reader(1);
            let pubkey = reader.read_string()?; // server public key.
            let pubkey = parse_public_key(pubkey)?;
            debug!("server_public_Key: {:?}", pubkey);
            let server_ephemeral = reader.read_string()?;
            kexdhdone.exchange.server_ephemeral.extend(server_ephemeral);
            let signature = reader.read_string()?;

            kexdhdone.kex.compute_shared_secret(
                &kexdhdone.exchange.server_ephemeral,
            )?;

            let hash = kexdhdone.kex.compute_exchange_hash(
                &pubkey,
                &kexdhdone.exchange,
                &mut self.buffer,
            )?;
            debug!("exchange hash: {:?}", hash);
            let signature = {
                let mut sig_reader = signature.reader(0);
                let sig_type = sig_reader.read_string()?;
                debug!("sig_type: {:?}", sig_type);
                sig_reader.read_string()?
            };
            use thrussh_keys::key::Verify;
            debug!("signature: {:?}", signature);
            assert!(pubkey.verify_server_auth(hash.as_ref(), signature));
            hash
        };
        if let Some(ref mut buffer) = session.0.buffer {
            let mut newkeys = kexdhdone.compute_keys(
                hash,
                &mut self.buffer,
                buffer,
                false,
            )?;
            session.0.cipher.write(
                &[msg::NEWKEYS],
                &mut session.0.write_buffer,
            );
            session.0.kex = Some(Kex::NewKeys(newkeys));
            newkeys.sent = true;
        }
        Ok(())
    }


    /// Ask the server to close a channel, finishing any pending write and read.
    pub fn channel_close(&mut self, channel: ChannelId) {
        if let Some(ref mut s) = self.session {
            s.0.byte(channel, msg::CHANNEL_CLOSE);
        }
    }

    /// Gets a borrow to the connection's handler.
    pub fn handler(&self) -> &H {
        self.handler.as_ref().unwrap()
    }

    /// Gets a mutable borrow to the connection's handler.
    pub fn handler_mut(&mut self) -> &mut H {
        self.handler.as_mut().unwrap()
    }


    /// Tests whether a channel is open.
    pub fn is_channel_open(&self, channel: ChannelId) -> bool {
        if let Some(ref session) = self.session {
            if let Some(ref enc) = session.0.encrypted {
                return enc.channels.contains_key(&channel);
            }
        }
        false
    }


    /// Create a new client connection.
    pub fn new(
        config: Arc<Config>,
        stream: R,
        handler: H,
        timeout: Option<Delay>,
    ) -> Result<Self, Error> {
        let mut write_buffer = SSHBuffer::new();
        write_buffer.send_ssh_id(config.as_ref().client_id.as_bytes());
        let write = write_buffer.write_all(stream);
        let mut connection = Connection {
            read_buffer: Some(SSHBuffer::new()),
            timeout: timeout,
            session: Some(Session(CommonSession {
                write_buffer: write_buffer,
                kex: None,
                auth_user: String::new(),
                auth_method: None, // Client only.
                cipher: Arc::new(cipher::CLEAR_PAIR),
                encrypted: None,
                config: config,
                wants_reply: false,
                disconnected: false,
                buffer: Some(CryptoVec::new()),
            })),
            state: Some(ConnectionState::WriteSshId(write)),
            handler: Some(handler),
            buffer: CryptoVec::new(),
        };
        if let Some(ref mut s) = connection.session {
            try!(s.flush())
        }
        Ok(connection)
    }

    #[doc(hidden)]
    fn read_ssh_id(&mut self, sshid: &[u8]) -> Result<(), Error> {
        // self.read_buffer.bytes += sshid.bytes_read + 2;
        let mut exchange = Exchange::new();
        exchange.server_id.extend(sshid);
        // Preparing the response
        if let Some(ref mut s) = self.session {
            exchange.client_id.extend(
                s.0.config.as_ref().client_id.as_bytes(),
            );
            let mut kexinit = KexInit {
                exchange: exchange,
                algo: None,
                sent: false,
                session_id: None,
            };
            kexinit.client_write(
                s.0.config.as_ref(),
                &mut s.0.cipher,
                &mut s.0.write_buffer,
            )?;
            s.0.kex = Some(Kex::KexInit(kexinit));
        }
        Ok(())
    }
}




impl<R: AsyncRead + AsyncWrite + Tcp, H: Handler> Future for Connection<R, H> {
    type Item = ();
    type Error = HandlerError<H::Error>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // If timeout, shutdown the socket.
        try_ready!(self.poll_timeout()); // returns an error if there's a timeout.
        debug!("no timeout");
        if self.is_reading() {
            // the write buffer is in the connection, we can flush.
            self.flush()?;
            let needs_write = if let Some(ref mut session) = self.session {
                !session.0.write_buffer.buffer.is_empty()
            } else {
                false
            };
            if needs_write {
                self.abort_read()?
            }
        }
        loop {
            debug!("client polling");
            if let Status::Disconnect = try_ready!(self.atomic_poll()) {
                return Ok(Async::Ready(()));
            }
        }
    }
}
