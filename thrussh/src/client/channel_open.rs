use super::*;
use tokio::io::{AsyncRead, AsyncWrite};
use tcp::Tcp;

impl<R: AsyncRead + AsyncWrite, H: Handler> Connection<R, H> {
    /// Ask the server to open a session channel.
    pub fn channel_open_session(mut self) -> ChannelOpen<R, H, SessionChannel> {
        let num = if let Some(ref mut s) = self.session {
            s.channel_open_session().unwrap()
        } else {
            unreachable!()
        };
        ChannelOpen {
            connection: Some(self),
            channel: num,
            channel_type: PhantomData,
            first_round: true,
        }
    }

    /// Ask the server to open an X11 forwarding channel.
    pub fn channel_open_x11(
        mut self,
        originator_address: &str,
        originator_port: u32,
    ) -> ChannelOpen<R, H, X11Channel> {
        let num = if let Some(ref mut s) = self.session {
            s.channel_open_x11(originator_address, originator_port)
                .unwrap()
        } else {
            unreachable!()
        };
        ChannelOpen {
            connection: Some(self),
            channel: num,
            channel_type: PhantomData,
            first_round: true,
        }
    }

    /// Ask the server to open a direct TCP/IP forwarding channel.
    pub fn channel_open_direct_tcpip(
        mut self,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> ChannelOpen<R, H, DirectTcpIpChannel> {
        let num = if let Some(ref mut s) = self.session {
            s.channel_open_direct_tcpip(
                host_to_connect,
                port_to_connect,
                originator_address,
                originator_port,
            ).unwrap()
        } else {
            unreachable!()
        };
        ChannelOpen {
            connection: Some(self),
            channel: num,
            channel_type: PhantomData,
            first_round: true,
        }
    }
}
use std::marker::PhantomData;

#[doc(hidden)]
pub enum X11Channel {}
#[doc(hidden)]
pub enum SessionChannel {}
#[doc(hidden)]
pub enum DirectTcpIpChannel {}

/// A future resolving into an open channel number of type
/// `ChannelType`, which can be either `SessionChannel`, `X11Channel`
/// or `DirectTcpIdChannel`.
pub struct ChannelOpen<R: AsyncRead + AsyncWrite, H: Handler, ChannelType> {
    connection: Option<Connection<R, H>>,
    channel: ChannelId,
    channel_type: PhantomData<ChannelType>,
    first_round: bool,
}

impl<R: AsyncRead + AsyncWrite + Tcp, H: Handler, ChannelType> Future
    for ChannelOpen<R, H, ChannelType> {
    type Item = (Connection<R, H>, ChannelId);
    type Error = HandlerError<H::Error>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {

        if self.first_round {
            if let Some(ref mut c) = self.connection {
                c.abort_read()?;
            }
            self.first_round = false
        }
        loop {
            debug!("channelopen loop");
            let is_open = if let Some(ref c) = self.connection {
                if let Some(ref s) = c.session {
                    s.channel_is_open(self.channel) && c.is_reading()
                } else {
                    false
                }
            } else {
                false
            };
            if is_open {
                return Ok(Async::Ready(
                    (self.connection.take().unwrap(), self.channel),
                ));
            }

            let status = if let Some(ref mut c) = self.connection {
                try_ready!(c.atomic_poll())
            } else {
                unreachable!()
            };

            if let Status::Disconnect = status {
                return Err(HandlerError::Error(Error::Disconnect));
            }
        }
    }
}
