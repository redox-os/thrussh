use std;
use tokio::net::TcpStream;

/// Types that have a "TCP shutdown" operation.
pub trait Tcp {
    /// Shutdown the TCP connection cleanly.
    fn tcp_shutdown(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl Tcp for TcpStream {
    fn tcp_shutdown(&mut self) -> Result<(), std::io::Error> {
        debug!("tcp shutdown for tcpstream");
        self.shutdown(std::net::Shutdown::Both)
    }
}

impl<T: ?Sized + Tcp> Tcp for Box<T> {
    fn tcp_shutdown(&mut self) -> Result<(), std::io::Error> {
        self.as_mut().tcp_shutdown()
    }
}
impl<'a, T: ?Sized + Tcp> Tcp for &'a mut T {
    fn tcp_shutdown(&mut self) -> Result<(), std::io::Error> {
        (*self).tcp_shutdown()
    }
}
impl<'a> Tcp for std::io::Cursor<&'a mut [u8]> {}
impl Tcp for std::io::Cursor<Vec<u8>> {}
impl Tcp for std::io::Cursor<Box<[u8]>> {}
