use {Error, ErrorKind};
use tokio_io::io::{Flush, WriteAll, ReadExact};
use tokio_io::{AsyncRead, AsyncWrite};
use cryptovec::CryptoVec;
use futures::{Async, Poll, Future};
use encoding::Reader;
use byteorder::{BigEndian, ByteOrder};
use tokio_io;
use key::{PublicKey, SignatureHash};
use encoding::Encoding;
use key;

use super::msg;
use super::Constraint;

/// SSH agent client.
pub struct AgentClient<S: AsyncRead+AsyncWrite> {
    stream: S,
    buf: CryptoVec
}

enum State<S: AsyncRead+AsyncWrite> {
    ReadLen(ReadExact<S, CryptoVec>),
    Read(ReadExact<S, CryptoVec>),
    Write(WriteAll<S, CryptoVec>),
    Flush { flush: Flush<S>, buf: CryptoVec }
}

/// Future resolving to a response from the agent.
pub struct ReadResponse<S: AsyncRead+AsyncWrite>(Option<State<S>>);

impl<S: AsyncRead+AsyncWrite> Future for ReadResponse<S> {
    type Item = (AgentClient<S>, bool);
    type Error = Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.0.take() {
                Some(State::Write(mut w)) => {
                    if let Async::Ready((stream, buf)) = w.poll()? {
                        self.0 = Some(State::Flush {
                            buf,
                            flush: tokio_io::io::flush(stream)
                        })
                    } else {
                        self.0 = Some(State::Write(w));
                        return Ok(Async::NotReady)
                    }
                }
                Some(State::Flush { mut flush, mut buf }) => {
                    if let Async::Ready(stream) = flush.poll()? {
                        buf.clear();
                        buf.resize(4);
                        self.0 = Some(State::ReadLen(tokio_io::io::read_exact(stream, buf)))
                    } else {
                        self.0 = Some(State::Flush { flush, buf });
                        return Ok(Async::NotReady)
                    }
                }
                Some(State::ReadLen(mut read)) => {
                    if let Async::Ready((stream, mut buf)) = read.poll()? {
                        let len = BigEndian::read_u32(&buf) as usize;
                        buf.clear();
                        buf.resize(len);
                        self.0 = Some(State::Read(tokio_io::io::read_exact(stream, buf)))
                    } else {
                        self.0 = Some(State::ReadLen(read));
                        return Ok(Async::NotReady)
                    }
                }
                Some(State::Read(mut read)) => {
                    if let Async::Ready((stream, buf)) = read.poll()? {
                        let success = !buf.is_empty() && buf[0] == msg::SUCCESS;
                        return Ok(Async::Ready((AgentClient { stream, buf }, success)))
                    } else {
                        self.0 = Some(State::ReadLen(read));
                        return Ok(Async::NotReady)
                    }
                }
                _ => panic!("future called after yielded")
            }
        }
    }
}

/// Future resolving to a response from the agent.
pub struct RequestIdentities<S: AsyncRead+AsyncWrite>(ReadResponse<S>);

impl<S: AsyncRead+AsyncWrite> Future for RequestIdentities<S> {
    type Item = (AgentClient<S>, Option<Vec<PublicKey>>);
    type Error = Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Async::Ready((agent, _)) = self.0.poll()? {
            let mut keys = Vec::new();
            if agent.buf[0] == msg::IDENTITIES_ANSWER {
                let mut r = agent.buf.reader(1);
                let n = r.read_u32()?;
                for _ in 0..n {
                    let key = r.read_string()?;
                    let mut r = key.reader(0);
                    let t = r.read_string()?;
                    match t {
                        b"ssh-rsa" => {
                            let e = r.read_mpint()?;
                            let n = r.read_mpint()?;
                            use openssl::rsa::Rsa;
                            use openssl::bn::BigNum;
                            use openssl::pkey::PKey;
                            keys.push(PublicKey::RSA {
                                key: key::OpenSSLPKey(PKey::from_rsa(Rsa::from_public_components(
                                    BigNum::from_slice(n)?,
                                    BigNum::from_slice(e)?,
                                )?)?),
                                hash: SignatureHash::SHA2_512
                            })
                        }
                        b"ssh-ed25519" => {
                            let mut p = key::ed25519::PublicKey::new_zeroed();
                            p.key.clone_from_slice(r.read_string()?);
                            keys.push(PublicKey::Ed25519(p))
                        }
                        t => return Err(ErrorKind::UnsupportedKeyType(t.to_vec()).into())
                    }
                }
            }
            return Ok(Async::Ready((agent, Some(keys))))
        } else {
            return Ok(Async::NotReady)
        }
    }
}

/// Future resolving to a response from the agent.
pub struct SignRequest<S: AsyncRead+AsyncWrite>(ReadResponse<S>);

impl<S: AsyncRead+AsyncWrite> Future for SignRequest<S> {
    type Item = (AgentClient<S>, Option<CryptoVec>);
    type Error = Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Async::Ready((agent, _)) = self.0.poll()? {
            if agent.buf.is_empty() {
                return Ok(Async::Ready((agent, None)))
            } else if agent.buf[0] == msg::SIGN_RESPONSE {
                let sig = {
                    let mut r = agent.buf.reader(1);
                    CryptoVec::from_slice(r.read_string()?)
                };
                return Ok(Async::Ready((agent, Some(sig))))
            } else {
                return Ok(Async::Ready((agent, None)))
            }
        } else {
            return Ok(Async::NotReady)
        }
    }
}

/// Future resolving to a response from the agent.
pub struct QueryExtension<S: AsyncRead+AsyncWrite>(ReadResponse<S>, Option<CryptoVec>);

impl<S: AsyncRead+AsyncWrite> Future for QueryExtension<S> {
    type Item = (AgentClient<S>, CryptoVec, bool);
    type Error = Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Async::Ready((agent, _)) = self.0.poll()? {
            let mut buf = self.1.take().unwrap();
            if agent.buf[0] == msg::SUCCESS {
                {
                    let mut r = agent.buf.reader(1);
                    buf.extend(r.read_string()?)
                }
                return Ok(Async::Ready((agent, buf, true)))
            } else {
                return Ok(Async::Ready((agent, buf, false)))
            }
        } else {
            return Ok(Async::NotReady)
        }
    }
}

// https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-4.1

impl<S: AsyncRead+AsyncWrite> AgentClient<S> {

    /// Build a future that connects to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub fn connect(stream: S) -> AgentClient<S> {
        AgentClient { stream, buf: CryptoVec::new() }
    }

    /// Send a key to the agent, with a (possibly empty) slice of
    /// constraints to apply when using the key to sign.
    pub fn add_identity(mut self, key: &key::KeyPair, constraints: &[Constraint]) -> ReadResponse<S> {
        use encoding::Encoding;
        self.buf.clear();
        self.buf.resize(4);
        if constraints.is_empty() {
            self.buf.push(msg::ADD_IDENTITY)
        } else {
            self.buf.push(msg::ADD_ID_CONSTRAINED)
        }
        match *key {
            key::KeyPair::Ed25519(ref secret) => {
                self.buf.extend_ssh_string(b"ssh-ed25519");
                let public = &secret.key[32..];
                self.buf.extend_ssh_string(public);
                self.buf.push_u32_be(64);
                self.buf.extend(&secret.key);
                self.buf.extend_ssh_string(b"");
            }
            key::KeyPair::RSA { ref key, .. } => {
                self.buf.extend_ssh_string(b"ssh-rsa");
                self.buf.extend_ssh_mpint(&key.n().to_vec());
                self.buf.extend_ssh_mpint(&key.e().to_vec());
                self.buf.extend_ssh_mpint(&key.d().to_vec());
                self.buf.extend_ssh_mpint(&key.iqmp().unwrap().to_vec());
                self.buf.extend_ssh_mpint(&key.p().unwrap().to_vec());
                self.buf.extend_ssh_mpint(&key.q().unwrap().to_vec());
                self.buf.extend_ssh_string(b"");
            }
        }
        if !constraints.is_empty() {
            self.buf.push_u32_be(constraints.len() as u32);
            for cons in constraints {
                match *cons {
                    Constraint::KeyLifetime { seconds } => {
                        self.buf.push(msg::CONSTRAIN_LIFETIME);
                        self.buf.push_u32_be(seconds)
                    }
                    Constraint::Confirm => self.buf.push(msg::CONSTRAIN_CONFIRM),
                    Constraint::Extensions { ref name, ref details } => {
                        self.buf.push(msg::CONSTRAIN_EXTENSION);
                        self.buf.extend_ssh_string(name);
                        self.buf.extend_ssh_string(details);
                    },
                }
            }
        }
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        ReadResponse(Some(State::Write(tokio_io::io::write_all(self.stream, self.buf))))
    }

    /// Add a smart card to the agent, with a (possibly empty) set of
    /// constraints to apply when signing.
    pub fn add_smartcard_key(mut self, id: &str, pin: &[u8], constraints: &[Constraint]) -> ReadResponse<S> {
        use encoding::Encoding;
        self.buf.clear();
        self.buf.resize(4);
        if constraints.is_empty() {
            self.buf.push(msg::ADD_SMARTCARD_KEY)
        } else {
            self.buf.push(msg::ADD_SMARTCARD_KEY_CONSTRAINED)
        }
        self.buf.extend_ssh_string(id.as_bytes());
        self.buf.extend_ssh_string(pin);
        if !constraints.is_empty() {
            self.buf.push_u32_be(constraints.len() as u32);
            for cons in constraints {
                match *cons {
                    Constraint::KeyLifetime { seconds } => {
                        self.buf.push(msg::CONSTRAIN_LIFETIME);
                        self.buf.push_u32_be(seconds)
                    }
                    Constraint::Confirm => self.buf.push(msg::CONSTRAIN_CONFIRM),
                    Constraint::Extensions { ref name, ref details } => {
                        self.buf.push(msg::CONSTRAIN_EXTENSION);
                        self.buf.extend_ssh_string(name);
                        self.buf.extend_ssh_string(details);
                    },
                }
            }
        }
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        ReadResponse(Some(State::Write(tokio_io::io::write_all(self.stream, self.buf))))
    }

    /// Lock the agent, making it refuse to sign until unlocked.
    pub fn lock(mut self, passphrase: &[u8]) -> ReadResponse<S> {
        use encoding::Encoding;
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::LOCK);
        self.buf.extend_ssh_string(passphrase);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        ReadResponse(Some(State::Write(tokio_io::io::write_all(self.stream, self.buf))))
    }

    /// Unlock the agent, allowing it to sign again.
    pub fn unlock(mut self, passphrase: &[u8]) -> ReadResponse<S> {
        use encoding::Encoding;
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::UNLOCK);
        self.buf.extend_ssh_string(passphrase);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        ReadResponse(Some(State::Write(tokio_io::io::write_all(self.stream, self.buf))))
    }

    /// Ask the agent for a list of the currently registered secret
    /// keys.
    pub fn request_identities(mut self) -> RequestIdentities<S> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REQUEST_IDENTITIES);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        RequestIdentities(ReadResponse(Some(State::Write(
            tokio_io::io::write_all(self.stream, self.buf)
        ))))
    }

    /// Ask the agent to sign the supplied piece of data.
    pub fn sign_request(mut self, public: &key::PublicKey, data: &[u8]) -> SignRequest<S> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::SIGN_REQUEST);
        key_blob(public, &mut self.buf);
        self.buf.extend_ssh_string(data);
        match *public {
            PublicKey::RSA { hash, .. } =>
                self.buf.push_u32_be(match hash {
                    SignatureHash::SHA2_256 => 2,
                    SignatureHash::SHA2_512 => 4,
                }),
            _ => self.buf.push_u32_be(0),
        }
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        SignRequest(ReadResponse(Some(State::Write(tokio_io::io::write_all(self.stream, self.buf)))))
    }

    /// Ask the agent to remove a key from its memory.
    pub fn remove_identity(mut self, public: &key::PublicKey) -> ReadResponse<S> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REMOVE_IDENTITY);
        key_blob(public, &mut self.buf);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        ReadResponse(Some(State::Write(tokio_io::io::write_all(self.stream, self.buf))))
    }

    /// Ask the agent to remove a smartcard from its memory.
    pub fn remove_smartcard_key(mut self, id: &str, pin: &[u8]) -> ReadResponse<S> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REMOVE_SMARTCARD_KEY);
        self.buf.extend_ssh_string(id.as_bytes());
        self.buf.extend_ssh_string(pin);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        ReadResponse(Some(State::Write(tokio_io::io::write_all(self.stream, self.buf))))
    }

    /// Ask the agent to forget all known keys.
    pub fn remove_all_identities(mut self) -> ReadResponse<S> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REMOVE_ALL_IDENTITIES);
        BigEndian::write_u32(&mut self.buf[0..], 5);
        ReadResponse(Some(State::Write(tokio_io::io::write_all(self.stream, self.buf))))
    }

    /// Send a custom message to the agent.
    pub fn extension(mut self, typ: &[u8], ext: &[u8]) -> ReadResponse<S> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::EXTENSION);
        self.buf.extend_ssh_string(typ);
        self.buf.extend_ssh_string(ext);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        ReadResponse(Some(State::Write(tokio_io::io::write_all(self.stream, self.buf))))
    }

    /// Ask the agent what extensions about supported extensions.
    pub fn query_extension(mut self, typ: &[u8], ext: CryptoVec) -> QueryExtension<S> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::EXTENSION);
        self.buf.extend_ssh_string(typ);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        QueryExtension(
            ReadResponse(Some(State::Write(tokio_io::io::write_all(self.stream, self.buf)))),
            Some(ext)
        )
    }

}

fn key_blob(public: &key::PublicKey, buf: &mut CryptoVec) {
    match *public {
        PublicKey::RSA{ ref key, .. } => {
            buf.extend(&[0, 0, 0, 0]);
            let len0 = buf.len();
            buf.extend_ssh_string(b"ssh-rsa");
            let rsa = key.0.rsa().unwrap();
            buf.extend_ssh_mpint(&rsa.e().to_vec());
            buf.extend_ssh_mpint(&rsa.n().to_vec());
            let len1 = buf.len();
            BigEndian::write_u32(&mut buf[5..], (len1 - len0) as u32);
        }
        PublicKey::Ed25519(ref p) => {
            buf.extend(&[0, 0, 0, 0]);
            let len0 = buf.len();
            buf.extend_ssh_string(b"ssh-ed25519");
            buf.extend_ssh_string(&p.key[0..]);
            let len1 = buf.len();
            BigEndian::write_u32(&mut buf[5..], (len1 - len0) as u32);
        }
    }
}
