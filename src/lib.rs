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
//! **A confirmed request's client is answered after the whole receive
//! cycle**: it waits for a Simple-ACK, sent on
//! [`transport::Verdict::Accepted`]; on [`transport::Verdict::Refused`] an
//! answer it does not send again (ASHRAE 135 clauses 18 and 20.1) — an Error
//! (class `services`, code `service-request-denied`) for a client not
//! identified or not permitted, a Reject (`inconsistent-parameters`) for
//! content refused; an Error (class `resources`, code `other`), sent on
//! [`transport::Verdict::Failed`], after which it may send the request again
//! ([`confirmed`]). Everything else — an unconfirmed request,
//! a broadcast, a segmented request — has nobody waiting on it, and is
//! at-most-once ([`AT_MOST_ONCE`]). Each NPDU arrives whole.
//!
//! The origin URI carries what the frame knew: `bacnet://peer?function=0a`.

pub mod confirmed;

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use transport::answer::Datagram;
use transport::bound::{Bound, Reading};
use transport::error::{Result, classify, protocol_error};
use transport::kept::Kept;
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::sender::Sender;
use transport::socket;
use transport::{Acknowledgement, Arrived, Configured, Directions, Taken, Transport};
use xcore::settings::{Applies, Kind, Presence, Read, Setting, Settings};

use crate::confirmed::Confirmed;

/// Why an NPDU that is not a confirmed request cannot be acknowledged after
/// the receive cycle.
pub const AT_MOST_ONCE: &str = "a BACnet NPDU that is not a confirmed request in one segment \
                                has nobody waiting on an answer: it is a datagram";

/// The BVLC type byte: BACnet/IP.
const BVLC_TYPE: u8 = 0x81;
/// Original-Unicast-NPDU.
const UNICAST: u8 = 0x0a;
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
    /// The socket every send leaves from, bound once.
    sender: Sender,
    /// The socket the first receive binds, and every receive reads.
    receiving: Kept<UdpSocket>,
}

impl BacnetTransport {
    /// Bind at `bind`; `0.0.0.0:47808` is the standard port.
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            receive_timeout: None,
            function: UNICAST,
            sender: Sender::new(),
            receiving: Kept::new(),
        }
    }

    /// Send as broadcast rather than unicast.
    #[must_use]
    pub fn broadcasting(mut self) -> Self {
        self.function = BROADCAST;
        self.sender = self.sender.broadcasting();
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
        let (socket, local) = socket::bind_udp(&self.bind, self.receive_timeout)?;
        if self.function == BROADCAST {
            socket
                .set_broadcast(true)
                .map_err(|e| classify("enabling broadcast", &e))?;
        }
        Ok((socket, local))
    }

    /// Take one frame from an already-bound socket, with who sent it.
    ///
    /// # Errors
    /// Where nothing arrived in time, or what arrived is not BACnet/IP.
    fn receive_frame(socket: &UdpSocket) -> Result<(Bvlc, SocketAddr)> {
        let mut buffer = vec![0u8; MAX_DATAGRAM];
        let (read, peer) = socket
            .recv_from(&mut buffer)
            .map_err(|e| classify("receiving a datagram", &e))?;
        Ok((read_frame(&buffer[..read])?, peer))
    }

    /// Take one frame from an already-bound socket, whole. A confirmed
    /// request's client waits for its answer until the receive cycle has
    /// ended: a Simple-ACK on accepted, an Error or a Reject it does not
    /// send again on refused, an Error it may send again on failed.
    /// Anything else is at-most-once ([`AT_MOST_ONCE`]).
    ///
    /// # Errors
    /// Where nothing arrived in time, what arrived is not BACnet/IP, or the
    /// socket could not be held for the answer.
    pub fn receive_one(&self, socket: &UdpSocket) -> Result<Arrived> {
        let (bvlc, peer) = Self::receive_frame(socket)?;
        let acknowledgement = match Confirmed::of(&bvlc.npdu) {
            Some(confirmed) => {
                let answering = Datagram::to(socket, peer)?;
                Acknowledgement::deferred(move |verdict| {
                    let answer = confirmed.answer(verdict);
                    answering.send(&frame(UNICAST, &answer)?)
                })
            }
            None => Acknowledgement::at_most_once(AT_MOST_ONCE),
        };
        Ok(Arrived::whole(
            format!("bacnet://{peer}?function={:02x}", bvlc.function),
            bvlc.npdu,
            acknowledgement,
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

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Unordered(
            "each request is its own, answered to its own sender by its invoke id",
        )
    }

    /// One frame, from the socket the first receive bound and kept: what
    /// arrived between two receives waits in its buffer. A confirmed
    /// request is answered after the receive cycle, Simple-ACK or Error;
    /// anything else is at-most-once ([`AT_MOST_ONCE`]).
    fn receive(&self) -> Result<Vec<Arrived>> {
        let socket = self.receiving.bound(|| self.bind())?;
        Ok(vec![self.receive_one(socket)?])
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        self.sender.send_to(&frame(self.function, bytes)?, target)
    }
}

impl Configured for BacnetTransport {
    /// The address is the local socket a Receive Location binds —
    /// `0.0.0.0:47808` the standard port; a Send Location sends to the target
    /// its route gives.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "broadcast",
                kind: Kind::Boolean,
                presence: Presence::Optional,
                meaning: "Whether NPDUs go out as Original-Broadcast rather than \
                          Original-Unicast; unicast when left out.",
                applies: Applies::Send,
            },
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a receive waits for a datagram; unbounded when left out.",
                applies: Applies::Receive,
            },
        ],
    };

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let mut transport = Self::new(address);
        if settings.optional_boolean("broadcast") == Some(true) {
            transport = transport.broadcasting();
        }
        if let Some(timeout) = settings.optional_duration("timeout") {
            transport = transport.timing_out_after(timeout);
        }
        Ok(transport)
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
    fn take_one(self, socket: &UdpSocket) -> Result<Taken> {
        let mut bytes = Vec::new();
        loop {
            let (bvlc, peer) = BacnetTransport::receive_frame(socket)?;
            socket
                .send_to(&frame(self.function, &[])?, peer)
                .map_err(|e| classify("acknowledging an NPDU", &e))?;
            if bvlc.npdu.is_empty() {
                let origin = format!("bacnet://{peer}?function={:02x}", bvlc.function);
                return Ok(Taken::new(origin, bytes));
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
            Self::receive_frame(&own)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::payload::edge_payloads;
    use xcore::settings::Given;

    #[test]
    fn bacnet_declares_its_settings_and_reads_through_them() {
        assert_eq!(BacnetTransport::SETTINGS.problems(), Vec::<String>::new());
        let given = [("broadcast".to_string(), Given::Boolean(true))];
        let sending = BacnetTransport::open("0.0.0.0:47808", Applies::Send, &given).expect("send");
        assert_eq!(sending.function, BROADCAST);
        let given = [("timeout".to_string(), Given::Text("2s".to_string()))];
        let receiving =
            BacnetTransport::open("0.0.0.0:47808", Applies::Receive, &given).expect("receive");
        assert_eq!(receiving.receive_timeout, Some(Duration::from_secs(2)));
        assert_eq!(receiving.function, UNICAST);
        let Err(refused) = BacnetTransport::open("0.0.0.0:47808", Applies::Send, &given) else {
            panic!("timeout is a receive setting");
        };
        assert!(
            refused.message.contains("\"timeout\""),
            "{}",
            refused.message
        );
    }

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
        assert!(arrived.defers(), "a confirmed request's client waits");
        let arrived = arrived.taken().expect("taken");
        assert_eq!(arrived.bytes, [0x01, 0x04, 0x00, 0x05, 0x01, 0x0c]);
        assert!(
            arrived.origin_uri.ends_with("?function=0a"),
            "{}",
            arrived.origin_uri
        );
    }

    #[test]
    fn a_confirmed_request_is_answered_after_the_cycle_and_the_rest_is_at_most_once() {
        const WRITE: [u8; 8] = [0x01, 0x04, 0x00, 0x05, 0x07, 0x0f, 0x0c, 0x00];
        let receiver = BacnetTransport::new("127.0.0.1:0").timing_out_after(Duration::from_secs(2));
        let (socket, address) = receiver.bind().expect("binding");
        let client = BacnetTransport::new("127.0.0.1:0").timing_out_after(Duration::from_secs(2));
        let (own, _) = client.bind().expect("the client's socket");
        let send = |npdu: &[u8]| {
            own.send_to(&frame(UNICAST, npdu).expect("frame"), &address)
                .expect("sent");
        };
        // Refused: the client is answered a Reject, and does not send again.
        send(&WRITE);
        let refused = receiver.receive_one(&socket).expect("refused");
        assert!(refused.defers());
        refused
            .refused(transport::Refusal::Unacceptable)
            .expect("rejected");
        let (answer, _) = BacnetTransport::receive_frame(&own).expect("answered");
        assert_eq!(answer.npdu, [0x01, 0x00, 0x60, 0x07, 0x02], "a Reject");
        // Failed: the client is answered Error `resources`, and sends again.
        send(&WRITE);
        let first = receiver.receive_one(&socket).expect("first");
        first.failed().expect("failed");
        let (answer, _) = BacnetTransport::receive_frame(&own).expect("answered");
        assert_eq!(answer.npdu[2], 0x50, "an Error: {:?}", answer.npdu);
        assert_eq!(answer.npdu[5..], [0x91, 0x03, 0x91, 0x00], "resources");
        // Accepted: the client is answered Simple-ACK.
        send(&WRITE);
        let again = receiver.receive_one(&socket).expect("again");
        assert_eq!(again.taken().expect("accepted").bytes, WRITE);
        let (answer, _) = BacnetTransport::receive_frame(&own).expect("answered");
        assert_eq!(answer.npdu, [0x01, 0x00, 0x20, 0x07, 0x0f]);
        // Who-Is: nobody waits.
        send(&[0x01, 0x00, 0x10, 0x08]);
        let unconfirmed = receiver.receive_one(&socket).expect("who-is");
        assert!(
            !unconfirmed.defers(),
            "an unconfirmed request is at-most-once"
        );
    }

    #[test]
    fn every_receive_reads_the_socket_the_first_bound() {
        let receiver = BacnetTransport::loopback();
        receiver.receiving.bound(|| receiver.bind()).expect("bound");
        let address = receiver.receiving.address().expect("address");
        transport::kept::held_across_receives(&receiver, address, 5, |at, payload| {
            BacnetTransport::loopback().send(at, payload)
        });
    }

    #[test]
    fn a_socket_has_no_artefact_to_claim() {
        assert!(BacnetTransport::new("127.0.0.1:0").claims().is_none());
        assert_eq!(BacnetTransport::new("127.0.0.1:0").name(), "bacnet");
    }
}
