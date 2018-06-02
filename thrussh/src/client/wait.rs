use super::*;
use tokio::io::{AsyncRead, AsyncWrite};
use tcp::Tcp;

impl<R: AsyncRead + AsyncWrite, H: Handler> Connection<R, H> {
    /// Wait until a condition is met on the connection.
    pub fn wait<F: Fn(&Connection<R, H>) -> bool>(self, f: F) -> Wait<R, H, F> {
        Wait {
            connection: Some(self),
            condition: f,
            first_round: true,
        }
    }

    /// Flush the session, sending any pending message.
    pub fn wait_flush(self) -> WaitFlush<R, H> {
        WaitFlush {
            connection: Some(self),
            first_round: true,
        }
    }
}

/// A future waiting for a channel to be closed.
pub struct Wait<R: AsyncRead + AsyncWrite, H: Handler, F> {
    connection: Option<Connection<R, H>>,
    condition: F,
    first_round: bool,
}

impl<R: AsyncRead + AsyncWrite + Tcp, H: Handler, F: Fn(&Connection<R, H>) -> bool> Future
    for Wait<R, H, F> {
    type Item = Connection<R, H>;
    type Error = HandlerError<H::Error>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if self.first_round {
            if let Some(ref mut c) = self.connection {
                c.abort_read()?
            }
            self.first_round = false
        }

        loop {
            debug!("wait loop");
            if let Some(mut connection) = self.connection.take() {
                if connection.handler.is_some() && (self.condition)(&connection) &&
                    connection.is_reading()
                {
                    return Ok(Async::Ready(connection));
                } else {
                    match try!(connection.atomic_poll()) {
                        Async::Ready(Status::Ok) => {
                            self.connection = Some(connection);
                        }
                        Async::Ready(Status::Disconnect) => return Ok(Async::Ready(connection)),
                        Async::NotReady => {
                            self.connection = Some(connection);
                            return Ok(Async::NotReady);
                        }
                    }
                }
            }
        }
    }
}


/// A future waiting for a flush request to complete.
pub struct WaitFlush<R: AsyncRead + AsyncWrite, H: Handler> {
    connection: Option<Connection<R, H>>,
    first_round: bool,
}


impl<R: AsyncRead + AsyncWrite + Tcp, H: Handler> Future for WaitFlush<R, H> {
    type Item = Connection<R, H>;
    type Error = HandlerError<H::Error>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if self.first_round {
            if let Some(ref mut c) = self.connection {
                c.abort_read()?
            }
            self.first_round = false
        }
        loop {
            debug!("WaitFlush loop");
            if let Some(mut c) = self.connection.take() {
                match try!(c.atomic_poll()) {
                    Async::Ready(Status::Disconnect) => return Ok(Async::Ready(c)),
                    Async::NotReady => {
                        self.connection = Some(c);
                        return Ok(Async::NotReady);
                    }
                    Async::Ready(Status::Ok) => {
                        match c.state {
                            Some(ConnectionState::Read(_)) => return Ok(Async::Ready(c)),
                            _ => self.connection = Some(c),
                        }
                    }
                }
            } else {
                unreachable!()
            }
        }
    }
}
