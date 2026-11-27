//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`.

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

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["bacnet"];
