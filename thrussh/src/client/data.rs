use super::connection::{Connection, ConnectionState};
use tokio::io::{AsyncRead, AsyncWrite};
use super::Handler;
use {ChannelId, HandlerError, Error, Status, AtomicPoll};
use futures::{Poll, Async, Future};
use tcp::Tcp;

impl<R: AsyncRead + AsyncWrite, H: Handler> Connection<R, H> {
    /// Send data to a channel. On session channels, `extended` can be
    /// used to encode standard error by passing `Some(1)`, and stdout
    /// by passing `None`.
    pub fn data<T: AsRef<[u8]>>(
        self,
        channel: ChannelId,
        extended: Option<u32>,
        data: T,
    ) -> Data<R, H, T> {

        debug!("data: {:?}", data.as_ref().len());
        Data {
            connection: Some(self),
            channel: channel,
            extended: extended,
            data: Some(data),
            position: 0,
            first_round: true,
        }
    }
}

/// Future for sending data.
pub struct Data<R: AsyncRead + AsyncWrite, H: Handler, T: AsRef<[u8]>> {
    connection: Option<Connection<R, H>>,
    data: Option<T>,
    extended: Option<u32>,
    channel: ChannelId,
    position: usize,
    first_round: bool,
}

// We are careful here, to leave the connection in the Read state (the
// only cancellable one) before returning Async::Ready.
impl<R: AsyncRead + AsyncWrite + Tcp, H: Handler, T: AsRef<[u8]>> Future for Data<R, H, T> {
    type Item = (Connection<R, H>, T);
    type Error = HandlerError<H::Error>;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {

        let mut connection = self.connection.take().unwrap();
        if self.first_round {
            connection.abort_read()?;
            self.first_round = false
        }
        let data = self.data.take().unwrap();

        loop {
            debug!("Data loop");
            // Do everything we can do.
            let status = connection.atomic_poll()?;
            let mut not_ready = false;
            match status {
                Async::Ready(Status::Disconnect) => return Err(From::from(Error::Disconnect)),
                Async::Ready(Status::Ok) if connection.is_reading() => {}
                Async::Ready(Status::Ok) => continue,
                Async::NotReady if connection.is_reading() => not_ready = true,
                Async::NotReady => {
                    self.connection = Some(connection);
                    self.data = Some(data);
                    return Ok(Async::NotReady);
                }
            }

            let mut session = connection.session.take().unwrap();
            {
                let data_ = data.as_ref();
                let enc = session.0.encrypted.as_mut().unwrap();
                self.position += enc.data(self.channel, self.extended, &data_[self.position..]);
            }
            session.flush()?;
            if !session.0.write_buffer.buffer.is_empty() {
                if let Some(ConnectionState::Read(mut read)) = connection.state {
                    if let Some((stream, read_buffer)) = read.try_abort() {
                        connection.read_buffer = Some(read_buffer);
                        connection.state = Some(ConnectionState::Write(
                            session.0.write_buffer.write_all(stream),
                        ));
                        connection.session = Some(session);
                    } else {
                        connection.state = Some(ConnectionState::Read(read));
                        connection.session = Some(session);
                    }
                } else {
                    connection.session = Some(session);
                }
            } else if self.position < data.as_ref().len() {
                connection.session = Some(session);
                if not_ready {
                    self.connection = Some(connection);
                    self.data = Some(data);
                    return Ok(Async::NotReady);
                }
            } else {
                connection.session = Some(session);
                return Ok(Async::Ready((connection, data)));
            }
        }
    }
}
