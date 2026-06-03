// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::socket::{SocketEventObserver, SocketEvents};

use crate::{events::IoEvents, process::signal::Pollee};

pub(super) struct RawIpObserver(Pollee);

impl RawIpObserver {
    pub(super) fn new(pollee: Pollee) -> Self {
        Self(pollee)
    }
}

impl SocketEventObserver for RawIpObserver {
    fn on_events(&self, events: SocketEvents) {
        if events.contains(SocketEvents::CAN_RECV) {
            self.0.notify(IoEvents::IN);
        }
        if events.contains(SocketEvents::CAN_SEND) {
            // RAW_SOCKET_STAGE3: Transmit queue space is surfaced as normal
            // writable readiness for Linux-style raw socket polling.
            self.0.notify(IoEvents::OUT);
        }
    }
}
