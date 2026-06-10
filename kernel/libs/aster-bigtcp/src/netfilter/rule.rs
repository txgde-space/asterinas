// SPDX-License-Identifier: MPL-2.0

use smoltcp::wire::Icmpv4Repr;

use super::hook::{HookPoint, Ipv4PacketContext, Verdict};

/// Describes the action selected by a netfilter rule.
///
/// NETFILTER_STAGE9: Keeping rule actions separate from hook verdicts mirrors
/// the future iptables model, where rules choose a target and the hook pipeline
/// converts that target into packet-processing behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    Accept,
    Drop,
}

impl From<Action> for Verdict {
    fn from(action: Action) -> Self {
        match action {
            Action::Accept => Self::Accept,
            Action::Drop => Self::Drop,
        }
    }
}

/// Matches packet metadata against one rule condition.
///
/// NETFILTER_STAGE9: This intentionally starts with the smallest matcher set
/// needed to preserve Stage 8 behavior. Later stages can add source/destination
/// address, protocol, port, and interface matchers without changing hook sites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Matcher {
    #[expect(
        dead_code,
        reason = "NETFILTER_STAGE14 keeps generic IPv4 matchers for later rule-list expansion"
    )]
    AnyIpv4,
    IcmpEchoIdentifier(u16),
}

impl Matcher {
    fn matches_ipv4(self, _context: Ipv4PacketContext<'_>) -> bool {
        matches!(self, Self::AnyIpv4)
    }

    fn matches_ipv4_icmpv4(
        self,
        context: Ipv4PacketContext<'_>,
        icmp_repr: &Icmpv4Repr<'_>,
    ) -> bool {
        match self {
            Self::AnyIpv4 => self.matches_ipv4(context),
            Self::IcmpEchoIdentifier(expected_ident) => {
                let Icmpv4Repr::EchoRequest { ident, .. } = icmp_repr else {
                    return false;
                };

                *ident == expected_ident
            }
        }
    }
}

/// Represents one immutable netfilter rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Rule {
    hook_point: HookPoint,
    matcher: Matcher,
    action: Action,
}

impl Rule {
    /// Creates a rule that drops ICMP Echo Requests with one identifier.
    #[expect(
        dead_code,
        reason = "NETFILTER_STAGE14 replaces the static test rule with a mutable OUTPUT list"
    )]
    pub(super) const fn drop_icmp_echo_identifier(hook_point: HookPoint, ident: u16) -> Self {
        Self {
            hook_point,
            matcher: Matcher::IcmpEchoIdentifier(ident),
            action: Action::Drop,
        }
    }

    /// Evaluates this rule against generic IPv4 metadata.
    pub(super) fn evaluate_ipv4(self, context: Ipv4PacketContext<'_>) -> Option<Verdict> {
        if self.hook_point != context.hook_point() || !self.matcher.matches_ipv4(context) {
            return None;
        }

        Some(self.action.into())
    }

    /// Evaluates this rule against IPv4 and ICMPv4 metadata.
    pub(super) fn evaluate_ipv4_icmpv4(
        self,
        context: Ipv4PacketContext<'_>,
        icmp_repr: &Icmpv4Repr<'_>,
    ) -> Option<Verdict> {
        if self.hook_point != context.hook_point()
            || !self.matcher.matches_ipv4_icmpv4(context, icmp_repr)
        {
            return None;
        }

        Some(self.action.into())
    }
}
