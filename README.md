# xmip-core-transport-bacnet

BACnet/IP transport: one BVLC-framed NPDU over UDP is one Stream, ASHRAE 135 Annex J. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location sends from one socket per address family, bound on its first send and kept by the transport and its clones (`transport::sender::Sender`), so an IPv6 target is reached too; until 2026-09-27 every send bound a new IPv4 socket.

A Receive Location keeps its socket, bound on the first receive (`transport::kept::Kept`): a datagram that arrives between two receives waits in its buffer for the next, where until 2026-09-27 each receive bound a socket of its own and a datagram sent between receives was lost.

## Acknowledgement

A confirmed request's client is answered after the whole receive cycle. The
transport reads the NPDU's network header and the APDU's first bytes, no
further: a confirmed request in one segment waits for its answer, a Simple-ACK
on Accepted. On Refused it is an answer the client does not send again (ASHRAE
135 clauses 18 and 20.1): an Error (class `services`, code
`service-request-denied`) for a client not identified or not permitted, a
Reject (reason `inconsistent-parameters`) for content refused. On Failed it is
an Error (class `resources`, code `other`), after which the client may send it
again; until 2026-10-02 that Error carried class 1, `object`, where `resources`
is 3. A routed request is answered back through
its router. Everything else, an unconfirmed request, a broadcast or a
segmented request, has nobody waiting on an answer and is at-most-once. Each
NPDU arrives whole. Which service it is, and its parameters, stay a contract's.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
