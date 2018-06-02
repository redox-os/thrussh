use super::connection::Connection;
use tokio::io::{AsyncRead, AsyncWrite};
use super::Handler;
use {HandlerError, Status, AtomicPoll};
use futures::{Poll, Async, Future};
use thrussh_keys::key;
use std::sync::Arc;
use tcp::Tcp;
use auth;

impl<R: AsyncRead + AsyncWrite + Tcp, H: Handler> Connection<R, H> {

    /// Try to authenticate this client using a password.
    pub fn authenticate_password(mut self, user: &str, password: String) -> Authenticate<R, H> {
        let is_waiting = if let Some(ref mut s) = self.session {
            let meth = auth::Method::Password { password };
            s.write_auth_request_if_needed(user, meth)
        } else { false };
        if is_waiting {
            self.abort_read().unwrap_or(());
        }
        Authenticate(Some(self))
    }

    /// Try to authenticate this client using a key pair.
    pub fn authenticate_key(mut self, user: &str, key: Arc<key::KeyPair>) -> Authenticate<R, H> {
        let is_waiting = if let Some(ref mut s) = self.session {
            let meth = auth::Method::PublicKey { key };
            s.write_auth_request_if_needed(user, meth)
        } else { false };
        if is_waiting {
            self.abort_read().unwrap_or(());
        }
        Authenticate(Some(self))
    }

    /// Try to authenticate this client using a key pair.
    pub fn authenticate_key_future(
        mut self,
        user: &str,
        key: key::PublicKey,
    ) -> Authenticate<R, H>
    {
        let is_waiting = if let Some(ref mut s) = self.session {
            let meth = auth::Method::FuturePublicKey { key };
            s.write_auth_request_if_needed(user, meth)
        } else { false };
        if is_waiting {
            self.abort_read().unwrap_or(());
        }
        Authenticate(Some(self))
    }
}

/// An authenticating future, ultimately resolving into an authenticated connection.
pub struct Authenticate<R: AsyncRead + AsyncWrite + Tcp, H: Handler>(Option<Connection<R, H>>);

impl<R: AsyncRead + AsyncWrite + Tcp, H: Handler> Future for Authenticate<R, H> {
    type Item = Connection<R, H>;
    type Error = HandlerError<H::Error>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            debug!("authenticated loop");
            let done = if let Some(ref c) = self.0 {
                c.is_reading() && {
                    if let Some(ref session) = c.session {
                        session.is_authenticated() || session.0.auth_method.is_none()
                    } else {
                        false
                    }
                }
            } else {
                false
            };
            if done {
                return Ok(Async::Ready(self.0.take().unwrap()))
            }
            let status = if let Some(ref mut c) = self.0 {
                debug!("atomic poll");
                try_ready!(c.atomic_poll())
            } else {
                unreachable!()
            };
            debug!("/atomic poll");

            if let Status::Disconnect = status {
                debug!("disconnect");
                return Ok(Async::Ready(self.0.take().unwrap()));
            }
        }
    }
}
