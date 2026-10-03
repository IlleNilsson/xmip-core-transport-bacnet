//! What this transport reads of the NPDU it carries: whether it is a
//! confirmed request a client waits on, and the answers it waits for
//! (ASHRAE 135 clauses 6.2 and 20.1). The service and its parameters stay a
//! contract's business.

use transport::{Refusal, Verdict};

/// The NPDU protocol version.
const VERSION: u8 = 0x01;
/// NPCI control: a network layer message, no APDU.
const NETWORK_MESSAGE: u8 = 0x80;
/// NPCI control: the destination specifier is present.
const DESTINATION: u8 = 0x20;
/// NPCI control: the source specifier is present.
const SOURCE: u8 = 0x08;
/// APDU type 0, a confirmed request, in the high nibble.
const CONFIRMED_REQUEST: u8 = 0x00;
/// The segmented-message bit of a confirmed request.
const SEGMENTED: u8 = 0x08;
/// APDU type 2, a Simple-ACK.
const SIMPLE_ACK: u8 = 0x20;
/// APDU type 5, an Error.
const ERROR: u8 = 0x50;
/// APDU type 6, a Reject: the request will not be carried out as sent
/// (clause 20.1.8, its reasons in clause 18.8).
const REJECT: u8 = 0x60;
/// Error class `resources` (3) and error code `other` (0), each an
/// application tagged enumerated of one byte (clause 18): the server could
/// not carry it out now, and the client may send it again.
const RESOURCES_OTHER: [u8; 4] = [0x91, 0x03, 0x91, 0x00];
/// Error class `services` (5) and error code `service-request-denied`
/// (29) (clause 18): the request from this client is denied, and sending
/// it again will not change that.
const SERVICE_REQUEST_DENIED: [u8; 4] = [0x91, 0x05, 0x91, 0x1d];
/// Reject reason `inconsistent-parameters` (2) (clause 18.8): what the
/// request carries is refused, and sending it again will not change that.
const INCONSISTENT_PARAMETERS: u8 = 0x02;
/// The hop count a routed answer starts with.
const HOP_COUNT: u8 = 0xff;

/// A confirmed request a client waits on: what its answer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirmed {
    /// The source network and address the request came from through a
    /// router, which the answer goes back to.
    routed_from: Option<(u16, Vec<u8>)>,
    invoke: u8,
    service: u8,
}

impl Confirmed {
    /// The confirmed request `npdu` is, where it is one in a single
    /// segment: `None` for an unconfirmed request, a network layer
    /// message, a segmented request, or anything this does not read.
    #[must_use]
    pub fn of(npdu: &[u8]) -> Option<Self> {
        let (&version, rest) = npdu.split_first()?;
        let (&control, mut rest) = rest.split_first()?;
        if version != VERSION || control & NETWORK_MESSAGE != 0 {
            return None;
        }
        if control & DESTINATION != 0 {
            let length = usize::from(*rest.get(2)?);
            rest = rest.get(3 + length..)?;
        }
        let mut routed_from = None;
        if control & SOURCE != 0 {
            let network = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]);
            let length = usize::from(*rest.get(2)?);
            routed_from = Some((network, rest.get(3..3 + length)?.to_vec()));
            rest = rest.get(3 + length..)?;
        }
        if control & DESTINATION != 0 {
            rest = rest.get(1..)?; // the hop count
        }
        match rest {
            [flags, _, invoke, service, ..]
                if flags & 0xf0 == CONFIRMED_REQUEST && flags & SEGMENTED == 0 =>
            {
                Some(Self {
                    routed_from,
                    invoke: *invoke,
                    service: *service,
                })
            }
            _ => None,
        }
    }

    /// The NPDU that answers it, as `verdict` says: a Simple-ACK on
    /// accepted; on refused, an Error of class `services`, code
    /// `service-request-denied`, for a client not identified or not
    /// permitted, and a Reject for `inconsistent-parameters` for content
    /// refused, neither sent again; on failed, an Error of class
    /// `resources`, code `other`, which the client may send again.
    #[must_use]
    pub fn answer(&self, verdict: Verdict) -> Vec<u8> {
        let mut out = vec![VERSION, 0];
        if let Some((network, address)) = &self.routed_from {
            out[1] = DESTINATION;
            out.extend_from_slice(&network.to_be_bytes());
            out.push(u8::try_from(address.len()).unwrap_or(0));
            out.extend_from_slice(address);
            out.push(HOP_COUNT);
        }
        let error = |out: &mut Vec<u8>, class_and_code: &[u8; 4]| {
            out.extend_from_slice(&[ERROR, self.invoke, self.service]);
            out.extend_from_slice(class_and_code);
        };
        match verdict {
            Verdict::Accepted => out.extend_from_slice(&[SIMPLE_ACK, self.invoke, self.service]),
            Verdict::Refused(Refusal::Unidentified | Refusal::Forbidden) => {
                error(&mut out, &SERVICE_REQUEST_DENIED);
            }
            Verdict::Refused(Refusal::Unacceptable) => {
                out.extend_from_slice(&[REJECT, self.invoke, INCONSISTENT_PARAMETERS]);
            }
            Verdict::Failed => error(&mut out, &RESOURCES_OTHER),
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `WriteProperty` request, invoke 7, unrouted.
    const WRITE: [u8; 8] = [0x01, 0x04, 0x00, 0x05, 0x07, 0x0f, 0x0c, 0x00];

    #[test]
    fn a_confirmed_request_is_answered_simple_ack_reject_or_error() {
        let confirmed = Confirmed::of(&WRITE).expect("confirmed");
        assert_eq!(
            confirmed.answer(Verdict::Accepted),
            [0x01, 0x00, 0x20, 0x07, 0x0f]
        );
        assert_eq!(
            confirmed.answer(Verdict::Refused(Refusal::Forbidden)),
            [0x01, 0x00, 0x50, 0x07, 0x0f, 0x91, 0x05, 0x91, 0x1d]
        );
        assert_eq!(
            confirmed.answer(Verdict::Refused(Refusal::Unacceptable)),
            [0x01, 0x00, 0x60, 0x07, 0x02]
        );
        assert_eq!(
            confirmed.answer(Verdict::Failed),
            [0x01, 0x00, 0x50, 0x07, 0x0f, 0x91, 0x03, 0x91, 0x00]
        );
    }

    #[test]
    fn a_routed_request_is_answered_back_through_its_router() {
        // Source network 5, a one-byte MAC 0x2a.
        let routed = [0x01, 0x0c, 0x00, 0x05, 0x01, 0x2a, 0x00, 0x05, 0x01, 0x0f];
        let confirmed = Confirmed::of(&routed).expect("confirmed");
        assert_eq!(
            confirmed.answer(Verdict::Accepted),
            [0x01, 0x20, 0x00, 0x05, 0x01, 0x2a, 0xff, 0x20, 0x01, 0x0f]
        );
        // Destination network 9, broadcast on it, hop count 255.
        let through = [0x01, 0x24, 0x00, 0x09, 0x00, 0xff, 0x00, 0x05, 0x02, 0x0f];
        assert_eq!(Confirmed::of(&through).expect("confirmed").invoke, 2);
    }

    #[test]
    fn what_no_client_waits_on_is_not_a_confirmed_request() {
        // Who-Is, unconfirmed.
        assert_eq!(
            Confirmed::of(&[0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08]),
            None
        );
        assert_eq!(Confirmed::of(&[0x01, 0x80, 0x00]), None, "network message");
        assert_eq!(
            Confirmed::of(&[0x01, 0x04, 0x08, 0x05, 0x07, 0x0f]),
            None,
            "segmented"
        );
        assert_eq!(Confirmed::of(b"who-is"), None);
        assert_eq!(Confirmed::of(&[]), None);
    }
}
