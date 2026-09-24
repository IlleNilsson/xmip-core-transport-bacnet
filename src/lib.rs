#![forbid(unsafe_code)]

//! Streams that arrive as BACnet/IP messages. One BVLC-framed NPDU is one
//! Stream.
//!
//! `BACnet` is the building: air handlers, chillers, meters, on UDP port 47808.
//! ASHRAE 135 Annex J puts a four-byte `BACnet` Virtual Link Control header in
//! front of every datagram — type `0x81`, a function, the total length — and
//! the network protocol data unit behind it is what Xmip carries. Unicast and
//! broadcast are the two functions a Location meets; the others, foreign-device
//! registration and the BBMD tables, are addressing and arrive with the
//! routing capability. Objects and properties are a contract's business.
//!
//! The origin URI carries what the frame knew: `bacnet://peer?function=0a`.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use transport::bound::{Bound, Reading};
use transport::error::{Result, classify, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::{Arrived, Directions, Transport};

/// The BVLC type byte: BACnet/IP.
pub const BVLC_TYPE: u8 = 0x81;
/// Original-Unicast-NPDU.
pub const UNICAST: u8 = 0x0a;
/// Original-Broadcast-NPDU.
pub const BROADCAST: u8 = 0x0b;
/// The largest datagram BACnet/IP allows, header included.
pub const MAX_DATAGRAM: usize = 1497;
/// The most NPDU one datagram carries: the datagram less the BVLC header.
pub const MAX_NPDU: usize = MAX_DATAGRAM - 4;

/// One BVLC frame, split.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bvlc {
    pub function: u8,
    pub npdu: Vec<u8>,
}

/// Frame `npdu` under `function`.
///
/// # Errors
/// An NPDU that with its header exceeds [`MAX_DATAGRAM`].
pub fn frame(function: u8, npdu: &[u8]) -> Result<Vec<u8>> {
    let total = npdu.len() + 4;
    if total > MAX_DATAGRAM {
        return Err(protocol_error(
            "an NPDU over what a BACnet/IP datagram may carry",
        ));
    }
    let length = u16::try_from(total).unwrap_or(0);
    let mut out = Vec::with_capacity(total);
    out.push(BVLC_TYPE);
    out.push(function);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(npdu);
    Ok(out)
}

/// Read one BVLC frame from a datagram.
///
/// # Errors
/// Not BACnet/IP, or a length that disagrees with the datagram.
pub fn read_frame(datagram: &[u8]) -> Result<Bvlc> {
    if datagram.len() < 4 || datagram[0] != BVLC_TYPE {
        return Err(protocol_error("a datagram that is not BACnet/IP"));
    }
    let length = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    if length != datagram.len() {
        return Err(protocol_error(
            "a BVLC length that disagrees with the datagram",
        ));
    }
    Ok(Bvlc {
        function: datagram[1],
        npdu: datagram[4..].to_vec(),
    })
}

#[derive(Clone)]
pub struct BacnetTransport {
    bind: String,
    receive_timeout: Option<Duration>,
    function: u8,
}

impl BacnetTransport {
    /// Bind at `bind`; `0.0.0.0:47808` is the standard port.
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            receive_timeout: None,
            function: UNICAST,
        }
    }

    /// Send as broadcast rather than unicast.
    #[must_use]
    pub const fn broadcasting(mut self) -> Self {
        self.function = BROADCAST;
        self
    }

    /// Give up waiting for a datagram after `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.receive_timeout = Some(timeout);
        self
    }

    /// Bind and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(UdpSocket, String)> {
        let socket = UdpSocket::bind(&self.bind).map_err(|e| classify("binding the socket", &e))?;
        if let Some(timeout) = self.receive_timeout {
            socket
                .set_read_timeout(Some(timeout))
                .map_err(|e| classify("setting the receive timeout", &e))?;
        }
        if self.function == BROADCAST {
            socket
                .set_broadcast(true)
                .map_err(|e| classify("enabling broadcast", &e))?;
        }
        let local = socket
            .local_addr()
            .map_err(|e| classify("reading the bound address", &e))?;
        Ok((socket, local.to_string()))
    }

    /// Take one frame from an already-bound socket, with who sent it.
    ///
    /// # Errors
    /// Where nothing arrived in time, or what arrived is not BACnet/IP.
    pub fn receive_frame(socket: &UdpSocket) -> Result<(Bvlc, SocketAddr)> {
        let mut buffer = vec![0u8; MAX_DATAGRAM];
        let (read, peer) = socket
            .recv_from(&mut buffer)
            .map_err(|e| classify("receiving a datagram", &e))?;
        Ok((read_frame(&buffer[..read])?, peer))
    }

    /// Take one frame from an already-bound socket.
    ///
    /// # Errors
    /// Where nothing arrived in time, or what arrived is not BACnet/IP.
    pub fn receive_one(&self, socket: &UdpSocket) -> Result<Arrived> {
        let (bvlc, peer) = Self::receive_frame(socket)?;
        Ok(Arrived::new(
            format!("bacnet://{peer}?function={:02x}", bvlc.function),
            bvlc.npdu,
        ))
    }
}

impl Transport for BacnetTransport {
    fn name(&self) -> &'static str {
        "bacnet"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn receive(&self) -> Result<Vec<Arrived>> {
        let (socket, _) = self.bind()?;
        Ok(vec![self.receive_one(&socket)?])
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let socket =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| classify("binding the sending socket", &e))?;
        if self.function == BROADCAST {
            socket
                .set_broadcast(true)
                .map_err(|e| classify("enabling broadcast", &e))?;
        }
        socket
            .send_to(&frame(self.function, bytes)?, target)
            .map_err(|e| classify("sending the datagram", &e))?;
        Ok(())
    }
}

impl BacnetTransport {
    /// Both ends on this machine: an ephemeral local port, the loopback
    /// timeout on every wait for a datagram.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0").timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Reading for BacnetTransport {
    /// A bound socket waiting for its NPDUs in order, each acknowledged with an
    /// empty NPDU back — the Simple-ACK a confirmed service earns, at the layer
    /// this transport speaks — and an empty one from the sender to close.
    fn take_one(self, socket: &UdpSocket) -> Result<Arrived> {
        let mut bytes = Vec::new();
        loop {
            let (bvlc, peer) = BacnetTransport::receive_frame(socket)?;
            socket
                .send_to(&frame(self.function, &[])?, peer)
                .map_err(|e| classify("acknowledging an NPDU", &e))?;
            if bvlc.npdu.is_empty() {
                let origin = format!("bacnet://{peer}?function={:02x}", bvlc.function);
                return Ok(Arrived::new(origin, bytes));
            }
            bytes.extend_from_slice(&bvlc.npdu);
        }
    }
}

/// A Stream longer than one NPDU travels as datagrams in order, each
/// acknowledged before the next goes. Sent unacknowledged, a burst of them
/// is flow-controlled by nothing but the far end's socket buffer, and a
/// mebibyte lost datagrams on loopback.
impl Loopback for BacnetTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Bound::new(self.clone(), self.bind()?)))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let near_end = self.clone();
        let (own, _) = near_end.bind()?;
        let close = std::iter::once(&[][..]);
        for npdu in payload.chunks(MAX_NPDU).chain(close) {
            own.send_to(&frame(near_end.function, npdu)?, address)
                .map_err(|e| classify("sending an NPDU", &e))?;
            near_end.receive_one(&own)?;
        }
        Ok(())
    }

    fn unblock(&self, _address: &str) {
        // Every wait has its own timeout; there is no listener to poke.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::payload::edge_payloads;

    #[test]
    fn a_loopback_round_carries_a_stream_as_datagrams() {
        let loopback = BacnetTransport::loopback();
        let arrived = loopback.round(b"who-is").expect("round");
        assert_eq!(arrived.bytes, b"who-is");
        assert!(arrived.origin_uri.starts_with("bacnet://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("?function=0a"));
        let long = vec![0x2a; 5000];
        assert_eq!(loopback.round(&long).expect("four datagrams").bytes, long);
        assert!(loopback.ceiling().is_none());
        assert!(loopback.refuses(&long).is_none());
    }

    #[test]
    fn the_loopback_returns_the_edges_whole() {
        let loopback = BacnetTransport::loopback();
        for (name, bytes) in edge_payloads() {
            let arrived = loopback
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
        }
    }

    #[test]
    fn a_frame_round_trips_and_a_bad_one_is_refused() {
        let framed = frame(UNICAST, &[0x01, 0x20, 0xff, 0xff, 0x00, 0xff]).expect("frame");
        assert_eq!(&framed[..4], &[0x81, 0x0a, 0x00, 0x0a]);
        let bvlc = read_frame(&framed).expect("bvlc");
        assert_eq!(bvlc.function, UNICAST);
        assert_eq!(bvlc.npdu, [0x01, 0x20, 0xff, 0xff, 0x00, 0xff]);
        assert!(
            read_frame(&[0x80, 0x0a, 0x00, 0x04]).is_err(),
            "not BACnet/IP"
        );
        assert!(
            read_frame(&[0x81, 0x0a, 0x00, 0x09, 0x01]).is_err(),
            "length disagrees"
        );
        assert!(frame(UNICAST, &[0; MAX_DATAGRAM]).is_err(), "too long");
    }

    #[test]
    fn a_datagram_arrives_with_its_function() {
        let receiver = BacnetTransport::new("127.0.0.1:0").timing_out_after(Duration::from_secs(2));
        let (socket, address) = receiver.bind().expect("binding");
        BacnetTransport::new("127.0.0.1:0")
            .send(&address, &[0x01, 0x04, 0x00, 0x05, 0x01, 0x0c])
            .expect("sending");
        let arrived = receiver.receive_one(&socket).expect("receiving");
        assert_eq!(arrived.bytes, [0x01, 0x04, 0x00, 0x05, 0x01, 0x0c]);
        assert!(
            arrived.origin_uri.ends_with("?function=0a"),
            "{}",
            arrived.origin_uri
        );
    }

    #[test]
    fn a_socket_has_no_artefact_to_claim() {
        assert!(BacnetTransport::new("127.0.0.1:0").claims().is_none());
        assert_eq!(BacnetTransport::new("127.0.0.1:0").name(), "bacnet");
    }
}
