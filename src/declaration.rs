//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48).

use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// Every setting a Location takes beyond its address, the local socket a
/// Receive Location binds — `0.0.0.0:47808` the standard port; a Send
/// Location sends to the target its route gives.
pub const SETTINGS: &Settings = &Settings {
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
        transport::configured::timeout(
            Applies::Receive,
            None,
            "How long a receive waits for a datagram; unbounded when left out.",
        ),
    ],
};

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["bacnet"];
