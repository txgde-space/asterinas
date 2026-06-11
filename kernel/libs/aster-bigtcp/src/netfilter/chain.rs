// SPDX-License-Identifier: MPL-2.0

use smoltcp::wire::Icmpv4Repr;

use super::{
    hook::{HookPoint, Ipv4PacketContext, Verdict},
    rule::{Action, Rule},
};

/// Represents one built-in IPv4 filter chain.
///
/// NETFILTER_STAGE10: A chain binds one hook point to ordered rules and a
/// default policy. This mirrors the iptables mental model more closely than a
/// flat rule list and gives later stages a natural home for INPUT/OUTPUT/FORWARD
/// chain management.
#[derive(Clone, Copy, Debug)]
pub(super) struct Chain {
    hook_point: HookPoint,
    policy: Action,
    rules: &'static [Rule],
}

impl Chain {
    /// Creates a built-in chain for one hook point.
    pub(super) const fn new(hook_point: HookPoint, policy: Action, rules: &'static [Rule]) -> Self {
        Self {
            hook_point,
            policy,
            rules,
        }
    }

    /// Returns whether this chain handles the given hook point.
    pub(super) fn handles(self, hook_point: HookPoint) -> bool {
        self.hook_point == hook_point
    }

    /// Evaluates generic IPv4 metadata against this chain.
    pub(super) fn evaluate_ipv4(self, context: Ipv4PacketContext<'_>) -> Verdict {
        for rule in self.rules {
            if let Some(verdict) = rule.evaluate_ipv4(context) {
                return verdict;
            }
        }

        self.policy.into()
    }

    /// Evaluates IPv4 ICMPv4 metadata against this chain.
    pub(super) fn evaluate_ipv4_icmpv4(
        self,
        context: Ipv4PacketContext<'_>,
        icmp_repr: &Icmpv4Repr<'_>,
    ) -> Verdict {
        for rule in self.rules {
            if let Some(verdict) = rule.evaluate_ipv4_icmpv4(context, icmp_repr) {
                return verdict;
            }
        }

        self.policy.into()
    }
}
