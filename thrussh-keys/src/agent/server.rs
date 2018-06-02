use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use cryptovec::CryptoVec;
use futures::{Future, Stream, Poll, Async};
use tokio_core::reactor::Handle;
use tokio_io::io::{read_exact, ReadExact, flush, Flush, write_all, WriteAll};
use tokio_io::{AsyncRead, AsyncWrite};
use byteorder::{BigEndian, ByteOrder};
use std::time::Duration;
use tokio_core::reactor::Timeout;
use std::time::SystemTime;
use key::SignatureHash;
use encoding::{Position, Reader, Encoding};
use key;

use {Error, ErrorKind};
use super::msg;
use super::Constraint;

#[derive(Clone)]
struct KeyStore(Arc<RwLock<HashMap<Vec<u8>, (key::KeyPair, SystemTime, Vec<Constraint>)>>>);

#[derive(Clone)]
struct Lock(Arc<RwLock<CryptoVec>>);

#[allow(missing_docs)]
#[derive(Debug)]
pub enum ServerError<E> {
    E(E),
    Error(Error)
}

pub trait Agent: Clone {
    type F: Future<Item = bool, Error = Error> + From<bool>;
    /// Called when data is about to be signed, and a confirmation is needed.
    #[allow(unused_variables)]
    fn confirm(&self, pk: &key::KeyPair) -> Self::F {
        From::from(false)
    }
}

/// The agent
pub struct AgentServer<S: AsyncRead+AsyncWrite, Addr, E, L: Stream<Item = (S, Addr), Error = E>, A: Agent> {
    listener: L,
    lock: Lock,
    keys: KeyStore,
    handle: Handle,
    agent: A,
}

impl<S: AsyncRead+AsyncWrite, Addr, E, L: Stream<Item = (S, Addr), Error = E>, A: Agent> AgentServer<S, Addr, E, L, A> {

    /// Create a new agent.
    pub fn new(listener: L, handle: Handle, agent: A) -> Self {
        AgentServer {
            listener,
            handle,
            agent,
            lock: Lock(Arc::new(RwLock::new(CryptoVec::new()))),
            keys: KeyStore(Arc::new(RwLock::new(HashMap::new()))),
        }
    }
}

impl<S: AsyncRead+AsyncWrite+'static, Addr, E, L: Stream<Item = (S, Addr), Error = E>, A: Agent+'static> Future for AgentServer<S, Addr, E, L, A> {
    type Item = ();
    type Error = ServerError<E>;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.listener.poll() {
                Ok(Async::Ready(Some((stream, _)))) => {
                    let mut buf = CryptoVec::new();
                    buf.resize(4);
                    self.handle.spawn(Connection {
                        lock: self.lock.clone(),
                        keys: self.keys.clone(),
                        state: Some(State::ReadLen(read_exact(stream, buf), CryptoVec::new())),
                        handle: self.handle.clone(),
                        agent: self.agent.clone(),
                    }.map_err(|e| eprintln!("{:?}", e)))
                }
                Ok(Async::Ready(None)) => return Ok(Async::Ready(())),
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => return Err(ServerError::E(e))
            }
        }
    }
}

struct Connection<S: AsyncRead+AsyncWrite, A: Agent> {
    lock: Lock,
    keys: KeyStore,
    state: Option<State<S, A>>,
    handle: Handle,
    agent: A,
}

enum State<S: AsyncRead+AsyncWrite, A: Agent> {
    ReadLen(ReadExact<S, CryptoVec>, CryptoVec),
    Read(ReadExact<S, CryptoVec>, CryptoVec),
    Write(WriteAll<S, CryptoVec>, CryptoVec),
    Respond { futures: Vec<A::F>, i: usize, stream: S, writebuf: CryptoVec, buf: CryptoVec },
    Flush(Flush<S>, CryptoVec, CryptoVec)
}

impl<S: AsyncRead+AsyncWrite, A: Agent> Future for Connection<S, A> {
    type Item = ();
    type Error = Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state.take() {
                Some(State::ReadLen(mut r, writebuf)) => {
                    if let Async::Ready((stream, mut buf)) = r.poll()? {
                        let len = BigEndian::read_u32(&buf) as usize;
                        buf.clear();
                        buf.resize(len);
                        self.state = Some(State::Read(read_exact(stream, buf), writebuf))
                    } else {
                        self.state = Some(State::ReadLen(r, writebuf));
                        return Ok(Async::NotReady)
                    }
                }
                Some(State::Read(mut r, mut writebuf)) => {
                    if let Async::Ready((stream, buf)) = r.poll()? {
                        writebuf.clear();
                        if let Some(v) = self.respond(&buf, &mut writebuf) {
                            self.state = Some(State::Respond { futures: v, i: 0, stream, writebuf, buf })
                        } else {
                            self.state = Some(State::Write(write_all(stream, writebuf), buf))
                        }
                    } else {
                        self.state = Some(State::Read(r, writebuf));
                        return Ok(Async::NotReady)
                    }
                }
                Some(State::Respond { mut futures, i, stream, mut writebuf, buf }) => {
                    // Validate constraints and sign.
                    if i >= futures.len() {
                        // All constraints passed!
                        {
                            let mut r = buf.reader(0);
                            r.read_byte()?;
                            self.really_sign(r, &mut writebuf)?;
                        }
                        self.state = Some(State::Write(write_all(stream, writebuf), buf))
                    } else {
                        match futures[i].poll()? {
                            Async::Ready(true) =>
                                self.state = Some(State::Respond {
                                    futures,
                                    i: i + 1,
                                    stream,
                                    writebuf,
                                    buf
                                }),
                            Async::Ready(false) => {
                                // failure
                                writebuf.resize(4);
                                writebuf.push(msg::FAILURE);
                                self.state = Some(State::Write(write_all(stream, writebuf), buf))
                            }
                            Async::NotReady => return Ok(Async::NotReady),
                        }
                    }
                }
                Some(State::Write(mut w, readbuf)) => {
                    if let Async::Ready((stream, buf)) = w.poll()? {
                        self.state = Some(State::Flush(flush(stream), readbuf, buf))
                    } else {
                        self.state = Some(State::Write(w, readbuf));
                        return Ok(Async::NotReady)
                    }
                }
                Some(State::Flush(mut w, mut readbuf, writebuf)) => {
                    if let Async::Ready(stream) = w.poll()? {
                        readbuf.clear();
                        readbuf.resize(4);
                        self.state = Some(State::ReadLen(read_exact(stream, readbuf), writebuf))
                    } else {
                        self.state = Some(State::Flush(w, readbuf, writebuf));
                        return Ok(Async::NotReady)
                    }
                }
                None => {
                    panic!("future polled after completion")
                }
            }
        }
    }
}

impl<S: AsyncRead+AsyncWrite, A: Agent> Connection<S, A> {

    fn respond(&self, buf: &CryptoVec, w: &mut CryptoVec) -> Option<Vec<A::F>> {
        let is_locked = {
            if let Ok(password) = self.lock.0.read() {
                !password.is_empty()
            } else {
                true
            }
        };
        w.extend(&[0, 0, 0, 0]);
        let mut r = buf.reader(0);
        match r.read_byte() {
            Ok(11) if !is_locked => {
                // request identities
                if let Ok(keys) = self.keys.0.read() {
                    w.push(msg::IDENTITIES_ANSWER);
                    w.push_u32_be(keys.len() as u32);
                    for (k, _) in keys.iter() {
                        w.extend_ssh_string(k);
                        w.extend_ssh_string(b"");
                    }
                } else {
                    w.push(msg::FAILURE)
                }
            }
            Ok(13) if !is_locked => {
                // sign request
                if let Ok(v) = self.try_sign(r) {
                    return Some(v)
                } else {
                    w.resize(4);
                    w.push(msg::FAILURE)
                }
            }
            Ok(17) if !is_locked => {
                // add identity
                if let Ok(true) = self.add_key(buf, w, r, false) {
                } else {
                    w.push(msg::FAILURE)
                }
            }
            Ok(18) if !is_locked => {
                // remove identity
                if let Ok(true) = self.remove_identity(r) {
                    w.push(msg::SUCCESS)
                } else {
                    w.push(msg::FAILURE)
                }
            }
            Ok(19) if !is_locked => {
                // remove all identities
                if let Ok(mut keys) = self.keys.0.write() {
                    keys.clear();
                    w.push(msg::SUCCESS)
                } else {
                    w.push(msg::FAILURE)
                }
            }
            Ok(22) if !is_locked => {
                // lock
                if let Ok(()) = self.lock(r) {
                    w.push(msg::SUCCESS)
                } else {
                    w.push(msg::FAILURE)
                }
            }
            Ok(23) if is_locked => {
                // unlock
                if let Ok(true) = self.unlock(r) {
                    w.push(msg::SUCCESS)
                } else {
                    w.push(msg::FAILURE)
                }
            }
            Ok(25) if !is_locked => {
                // add identity constrained
                if let Ok(true) = self.add_key(buf, w, r, true) {
                } else {
                    w.push(msg::FAILURE)
                }
            }
            _ => {
                // Message not understood
                w.push(msg::FAILURE)
            }
        }
        let len = w.len() - 4;
        BigEndian::write_u32(&mut w[0..], len as u32);
        None
    }

    fn lock(&self, mut r: Position) -> Result<(), Error> {
        let password = r.read_string()?;
        let mut lock = self.lock.0.write().map_err(|_| ErrorKind::Poison)?;
        lock.extend(password);
        Ok(())
    }

    fn unlock(&self, mut r: Position) -> Result<bool, Error> {
        let password = r.read_string()?;
        let mut lock = self.lock.0.write().map_err(|_| ErrorKind::Poison)?;
        if &lock[0..] == password {
            lock.clear();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn remove_identity(&self, mut r: Position) -> Result<bool, Error> {
        if let Ok(mut keys) = self.keys.0.write() {
            if keys.remove(r.read_string()?).is_some() {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }

    }

    fn add_key(&self, buf: &CryptoVec, w: &mut CryptoVec, mut r: Position, constrained: bool) -> Result<bool, Error> {
        let pos0 = r.position;
        let t = r.read_string()?;
        let (blob, key) = match t {
            b"ssh-ed25519" => {
                let public_ = r.read_string()?;
                let pos1 = r.position;
                let concat = r.read_string()?;
                let _comment = r.read_string()?;
                if &concat[32..64] != public_ {
                    return Ok(false)
                }
                use key::ed25519::*;
                let mut public = PublicKey::new_zeroed();
                let mut secret = SecretKey::new_zeroed();
                public.key.clone_from_slice(&public_[..32]);
                secret.key.clone_from_slice(&concat[..]);
                w.push(msg::SUCCESS);
                (buf[pos0..pos1].to_vec(),
                 key::KeyPair::Ed25519(secret))
            }
            b"ssh-rsa" => {
                use openssl::bn::{BigNum, BigNumContext};
                use openssl::rsa::Rsa;
                let n = r.read_mpint()?;
                let e = r.read_mpint()?;
                let d = BigNum::from_slice(r.read_mpint()?)?;
                let q_inv = r.read_mpint()?;
                let p = BigNum::from_slice(r.read_mpint()?)?;
                let q = BigNum::from_slice(r.read_mpint()?)?;
                let (dp, dq) = {
                    let one = BigNum::from_u32(1)?;
                    let p1 = p.as_ref() - one.as_ref();
                    let q1 = q.as_ref() - one.as_ref();
                    let mut context = BigNumContext::new()?;
                    let mut dp = BigNum::new()?;
                    let mut dq = BigNum::new()?;
                    dp.checked_rem(&d, &p1, &mut context)?;
                    dq.checked_rem(&d, &q1, &mut context)?;
                    (dp, dq)
                };
                let _comment = r.read_string()?;
                let key = Rsa::from_private_components (
                    BigNum::from_slice(n)?,
                    BigNum::from_slice(e)?,
                    d,
                    p,
                    q,
                    dp,
                    dq,
                    BigNum::from_slice(&q_inv)?,
                )?;

                let len0 = w.len();
                w.extend_ssh_string(b"ssh-rsa");
                w.extend_ssh_mpint(&e);
                w.extend_ssh_mpint(&n);
                let blob = w[len0..].to_vec();
                w.resize(len0);
                w.push(msg::SUCCESS);
                (blob, key::KeyPair::RSA { key, hash: SignatureHash::SHA2_256 })
            }
            _ => return Ok(false)
        };
        let mut w = self.keys.0.write().unwrap();
        let now = SystemTime::now();
        if constrained {
            let n = r.read_u32()?;
            let mut c = Vec::new();
            for _ in 0..n {
                let t = r.read_byte()?;
                if t == msg::CONSTRAIN_LIFETIME {
                    let seconds = r.read_u32()?;
                    c.push(Constraint::KeyLifetime { seconds });
                    let blob = blob.clone();
                    let keys = self.keys.clone();
                    self.handle.spawn(
                        Timeout::new(Duration::from_secs(seconds as u64), &self.handle).unwrap()
                            .map(move |_| {
                                let mut keys = keys.0.write().unwrap();
                                let delete = if let Some(&(_, time, _)) = keys.get(&blob) {
                                    time == now
                                } else {
                                    false
                                };
                                if delete {
                                    keys.remove(&blob);
                                }
                            })
                            .map_err(|_| ())
                    )
                } else if t == msg::CONSTRAIN_CONFIRM {
                    c.push(Constraint::Confirm)
                } else {
                    return Ok(false)
                }
            }
            w.insert(blob, (key, now, Vec::new()));
        } else {
            w.insert(blob, (key, now, Vec::new()));
        }
        Ok(true)
    }

    fn try_sign(&self, mut r: Position) -> Result<Vec<A::F>, Error> {
        let blob = r.read_string()?;
        let k = self.keys.0.read().unwrap();
        if let Some(&(ref key, _, ref constraints)) = k.get(blob) {
            let mut v = Vec::new();
            for cons in constraints {
                match *cons {
                    Constraint::KeyLifetime { .. } | Constraint::Extensions { .. } => {}
                    Constraint::Confirm => v.push(self.agent.confirm(key))
                }
            }
            Ok(v)
        } else {
            Ok(vec![A::F::from(false)])
        }
    }

    fn really_sign(&self, mut r: Position, w: &mut CryptoVec) -> Result<(), Error> {
        let blob = r.read_string()?;
        let data = r.read_string()?;
        let k = self.keys.0.read().unwrap();
        if let Some(&(ref key, _, _)) = k.get(blob) {
            w.push(msg::SIGN_RESPONSE);
            key.add_signature(w, data)?;
            let len = w.len();
            BigEndian::write_u32(&mut w[0..], (len-4) as u32);
        }
        Ok(())
    }
}
