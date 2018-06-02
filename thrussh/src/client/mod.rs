// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use std::sync::Arc;
use std;
use futures::{Poll, Async};
use futures::future::Future;
use tokio_timer::Sleep;
use tokio::net::TcpStream;
use tokio::io::{WriteAll, Flush, flush};
use tokio;
use std::net::ToSocketAddrs;
use {Disconnect, Error, Limits, Sig, ChannelOpenFailure, ChannelId,
     FromFinished, HandlerError, Status, AtomicPoll};
use thrussh_keys::key::parse_public_key;
use thrussh_keys::key;
use auth;
use negotiation;
use cryptovec::CryptoVec;
use session::*;
use sshbuffer::*;
use pty::Pty;

mod encrypted;

mod session;
pub use self::session::*;
mod connection;
pub use self::connection::*;
mod data;
mod authenticate;
mod kex;
mod channel_open;
mod wait;

pub use self::data::*;
pub use self::authenticate::*;
pub use self::kex::*;
pub use self::channel_open::*;
pub use self::wait::*;

/// The configuration of clients.
#[derive(Debug)]
pub struct Config {
    /// The client ID string sent at the beginning of the protocol.
    pub client_id: String,
    /// The bytes and time limits before key re-exchange.
    pub limits: Limits,
    /// The initial size of a channel (used for flow control).
    pub window_size: u32,
    /// The maximal size of a single packet.
    pub maximum_packet_size: u32,
    /// Lists of preferred algorithms.
    pub preferred: negotiation::Preferred,
    /// Time after which the connection is garbage-collected.
    pub connection_timeout: Option<std::time::Duration>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            client_id: format!(
                "SSH-2.0-{}_{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            ),
            limits: Limits::default(),
            window_size: 200000,
            maximum_packet_size: 200000,
            preferred: Default::default(),
            connection_timeout: None,
        }
    }
}


/// A client handler. Note that messages can be received from the
/// server at any time during a session.
pub trait Handler: Sized {
    /// Error type returned by the futures.
    type Error: std::fmt::Debug;

    /// A future ultimately resolving into a boolean, which can be
    /// returned by some parts of this handler.
    type FutureBool: Future<Item = (Self, bool), Error = Self::Error> + FromFinished<(Self, bool), Self::Error>;

    /// A future ultimately resolving into a boolean, which can be
    /// returned by some parts of this handler.
    type FutureUnit: Future<Item = Self, Error = Self::Error> + FromFinished<Self, Self::Error>;

    /// A future that computes the signature of a `CryptoVec`, appends
    /// that signature to that `CryptoVec`, and resolves to the
    /// `CryptoVec`. Useful for instance to implement SSH agent
    /// clients.
    type FutureSign: Future<Item = (Self, CryptoVec), Error = Self::Error> + FromFinished<(Self, CryptoVec), Self::Error>;

    /// A future ultimately resolving into unit, which can be returned
    /// by some parts of this handler.
    type SessionUnit: Future<Item = (Self, Session), Error = Self::Error> + FromFinished<(Self, Session), Self::Error>;


    /// Called when the server sends us an authentication banner. This
    /// is usually meant to be shown to the user, see
    /// [RFC4252](https://tools.ietf.org/html/rfc4252#section-5.4) for
    /// more details.
    #[allow(unused_variables)]
    fn auth_banner(self, banner: &str) -> Self::FutureUnit {
        Self::FutureUnit::finished(self)
    }

    /// Called when using the `FuturePublicKey` method, used for
    /// instance to implement SSH agent. This can be used for instance
    /// to implement an interface to SSH agents. The default
    /// implementation returns the supplied `CryptoVec` without
    /// touching it.
    #[allow(unused_variables)]
    fn auth_publickey_sign(self, key: &key::PublicKey, to_sign: CryptoVec) -> Self::FutureSign {
        Self::FutureSign::finished((self, to_sign))
    }

    /// Called to check the server's public key. This is a very important
    /// step to help prevent man-in-the-middle attacks. The default
    /// implementation rejects all keys.
    #[allow(unused_variables)]
    fn check_server_key(self, server_public_key: &key::PublicKey) -> Self::FutureBool {
        Self::FutureBool::finished((self, false))
    }

    /// Called when the server confirmed our request to open a
    /// channel. A channel can only be written to after receiving this
    /// message (this library panics otherwise).
    #[allow(unused_variables)]
    fn channel_open_confirmation(self, channel: ChannelId, session: Session) -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// Called when the server closes a channel.
    #[allow(unused_variables)]
    fn channel_close(self, channel: ChannelId, session: Session) -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// Called when the server sends EOF to a channel.
    #[allow(unused_variables)]
    fn channel_eof(self, channel: ChannelId, session: Session) -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// Called when the server rejected our request to open a channel.
    #[allow(unused_variables)]
    fn channel_open_failure(
        self,
        channel: ChannelId,
        reason: ChannelOpenFailure,
        description: &str,
        language: &str,
        session: Session,
    ) -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// Called when a new channel is created.
    #[allow(unused_variables)]
    fn channel_open_forwarded_tcpip(
        self,
        channel: ChannelId,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// Called when the server sends us data. The `extended_code`
    /// parameter is a stream identifier, `None` is usually the
    /// standard output, and `Some(1)` is the standard error. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2).
    #[allow(unused_variables)]
    fn data(
        self,
        channel: ChannelId,
        extended_code: Option<u32>,
        data: &[u8],
        session: Session,
    ) -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// The server informs this client of whether the client may
    /// perform control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    #[allow(unused_variables)]
    fn xon_xoff(
        self,
        channel: ChannelId,
        client_can_do: bool,
        session: Session,
    ) -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// The remote process has exited, with the given exit status.
    #[allow(unused_variables)]
    fn exit_status(
        self,
        channel: ChannelId,
        exit_status: u32,
        session: Session,
    ) -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// The remote process exited upon receiving a signal.
    #[allow(unused_variables)]
    fn exit_signal(
        self,
        channel: ChannelId,
        signal_name: Sig,
        core_dumped: bool,
        error_message: &str,
        lang_tag: &str,
        session: Session,
    ) -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// Called when the network window is adjusted, meaning that we
    /// can send more bytes. This is useful if this client wants to
    /// send huge amounts of data, for instance if we have called
    /// `Session::data` before, and it returned less than the
    /// full amount of data.
    #[allow(unused_variables)]
    fn window_adjusted(
        self,
        channel: ChannelId,
        new_window_size: usize,
        session: Session,
    ) -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }
}

/*
use tokio::reactor::Reactor;
/// Create a new client connection to the given address.
pub fn connect<
    Addr: ToSocketAddrs,
    H: Handler,
    I,
    E,
    X: Future<Item = I, Error = E>,
    F: FnOnce(Connection<TcpStream, H>) -> X,
>(
    addr: Addr,
    config: Arc<Config>,
    timeout: Option<Sleep>,
    handler: H,
    f: F,
) -> Result<I, HandlerError<E>> {

    let mut l = Reactor::new()?;
    let cur = tokio::executor::current_thread::CurrentThread::new();
    cur.block_on(connect_future(addr, config, timeout, handler, f)?)
}
*/

/// Create a new client connection to the given address.
pub fn connect_future<
    Addr: ToSocketAddrs,
    H: Handler,
    I,
    E,
    X: Future<Item = I, Error = E>,
    F: FnOnce(Connection<TcpStream, H>) -> X,
    >(
    addr: Addr,
    config: Arc<Config>,
    timeout: Option<Sleep>,
    handler: H,
    f: F,
) -> Result<ConnectFuture<H, I, E, X, F>, Error> {

    Ok(ConnectFuture {
        state: Some(ConnectFutureState::TcpConnect(
            TcpStream::connect(&addr.to_socket_addrs()?.next().unwrap())
        )),
        handler: Some(handler),
        config,
        timeout,
        f: Some(f),
    })
}

/// Future returned by `connect_future`.
pub struct ConnectFuture<H: Handler, I, E, X: Future<Item = I, Error = E>, F: FnOnce(Connection<TcpStream, H>) -> X> {
    handler: Option<H>,
    config: Arc<Config>,
    state: Option<ConnectFutureState<X>>,
    timeout: Option<Sleep>,
    f: Option<F>
}

enum ConnectFutureState<X> {
    TcpConnect(tokio::net::ConnectFuture),
    Connect(X)
}

impl<H: Handler, I, E, X: Future<Item = I, Error = E>, F: FnOnce(Connection<TcpStream, H>) -> X> Future for ConnectFuture<H, I, E, X, F> {
    type Item = I;
    type Error = HandlerError<E>;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state.take() {
                Some(ConnectFutureState::TcpConnect(mut connect)) => {
                    if let Async::Ready(socket) = connect.poll()? {

                        self.state = Some(ConnectFutureState::Connect(
                            (self.f.take().unwrap())(Connection::new(
                                self.config.clone(),
                                socket,
                                self.handler.take().unwrap(),
                                self.timeout.take(),
                            )?)
                        ))

                    } else {
                        self.state = Some(ConnectFutureState::TcpConnect(connect));
                        return Ok(Async::NotReady)
                    }
                }
                Some(ConnectFutureState::Connect(mut connect)) => {
                    match connect.poll() {
                        Ok(Async::Ready(f)) => return Ok(Async::Ready(f)),
                        Ok(Async::NotReady) => {
                            self.state = Some(ConnectFutureState::Connect(connect));
                            return Ok(Async::NotReady)
                        }
                        Err(e) => return Err(HandlerError::Handler(e))
                    }
                }
                None => panic!("Future polled after completion")
            }
        }
    }
}
