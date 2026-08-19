//! Deciding whether one trapped network syscall may reach the network.
//!
//! # Single responsibility
//! Answer "may this go out?" for a sandbox whose only egress is a local proxy.
//! It reads no memory, touches no descriptor and knows nothing about seccomp;
//! it is the rule, separated from the machinery that applies it.
//!
//! # Why it is its own module, and portable
//! Two supervisors need this answer — the CLI's and the lifecycle's — and two
//! implementations of "may this packet leave" is one more than can be kept
//! honest. Keeping it here rather than beside the Linux seccomp code also means
//! it compiles and is tested on every host, so the rule is not one that only a
//! Linux CI run ever reads.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// What a supervisor should do with a trapped network syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetVerdict {
    /// Let the syscall proceed.
    Allow,
    /// Fail it, without letting it reach the network.
    Deny,
}

/// The kinds of trapped syscall this rule distinguishes.
///
/// Named rather than numbered so the rule does not depend on Linux syscall
/// numbering, and so a host with no seccomp at all can still check it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetSyscall {
    /// `connect`, or a datagram send carrying a destination address.
    ///
    /// One variant for both on purpose. `sendto`, `sendmsg` and `sendmmsg`
    /// reach out exactly as `connect` does, and a rule that distinguished them
    /// would invite mediating one and not the others — which is how a policy
    /// ends up covering streams and leaving every datagram open.
    ReachOut,
    /// `bind`.
    Bind,
}

/// The part of a destination address this rule reads.
///
/// Deliberately two fields. Everything else about a `sockaddr` — the family,
/// the bytes of the address — is either irrelevant to the question or a way to
/// get it wrong: treating IPv4 and IPv6 loopback differently is how a
/// dual-stack host grows an escape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Destination {
    /// The port, in host byte order.
    pub port: u16,
    /// Whether the address is a loopback address, in either family.
    pub is_loopback: bool,
}

/// The one way out a proxy-mediated sandbox has.
///
/// Small on purpose: a proxy-only policy is not a rule set, it is a single
/// destination plus whatever the workload may listen on. Which *hosts* are
/// permitted is a question this layer cannot answer — it sees an address, and
/// the policy names a name.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ProxyOnlyPolicy {
    /// The loopback port the proxy listens on.
    pub proxy_port: u16,
    /// Ports the workload may bind.
    pub bind_ports: Vec<u16>,
    /// Inclusive port ranges the workload may bind.
    pub bind_port_ranges: Vec<(u16, u16)>,
}

impl ProxyOnlyPolicy {
    /// A policy whose only egress is `proxy_port`, and which may bind nothing.
    #[must_use]
    pub const fn to_proxy(proxy_port: u16) -> Self {
        Self {
            proxy_port,
            bind_ports: Vec::new(),
            bind_port_ranges: Vec::new(),
        }
    }

    /// Whether `port` is one this policy permits binding.
    #[must_use]
    pub fn may_bind(&self, port: u16) -> bool {
        self.bind_ports.contains(&port)
            || self
                .bind_port_ranges
                .iter()
                .any(|&(start, end)| port >= start && port <= end)
    }

    /// Decide one trapped syscall.
    ///
    /// **Loopback is half the test and cannot be dropped.** A port number alone
    /// permits reaching *any* host on that port, and the workload chooses the
    /// port it dials — that is not "through the proxy", it is "anywhere, as
    /// long as you use this number".
    #[must_use]
    pub fn decide(&self, syscall: NetSyscall, destination: Destination) -> NetVerdict {
        // A proxy on port 0 is not a proxy. Without this, a default-constructed
        // policy would match a connect to port 0 and let it through — a way out
        // opened by forgetting to fill a field in, which is the worst way for
        // one to appear.
        if self.proxy_port == 0 {
            return NetVerdict::Deny;
        }
        match syscall {
            NetSyscall::ReachOut => {
                if destination.is_loopback && destination.port == self.proxy_port {
                    NetVerdict::Allow
                } else {
                    NetVerdict::Deny
                }
            }
            NetSyscall::Bind => {
                if self.may_bind(destination.port) {
                    NetVerdict::Allow
                } else {
                    NetVerdict::Deny
                }
            }
        }
    }
}

impl fmt::Display for ProxyOnlyPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "egress only to 127.0.0.1:{}", self.proxy_port)?;
        if !self.bind_ports.is_empty() || !self.bind_port_ranges.is_empty() {
            write!(
                f,
                ", may bind {:?} and {:?}",
                self.bind_ports, self.bind_port_ranges
            )?;
        }
        Ok(())
    }
}

/// How many notifications a run may have refused, and how many it answered.
///
/// Counted rather than logged, because a count is checkable: a run that reports
/// zero refusals and zero decisions did not have a working listener, and
/// nothing else about it would say so.
#[derive(Debug, Default)]
pub struct ProxyNotifyStats {
    pub(super) decided: AtomicU64,
    pub(super) denied: AtomicU64,
}

impl ProxyNotifyStats {
    /// Notifications answered, of any verdict.
    #[must_use]
    pub fn decided(&self) -> u64 {
        self.decided.load(Ordering::Relaxed)
    }

    /// Notifications refused.
    #[must_use]
    pub fn denied(&self) -> u64 {
        self.denied.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROXY: u16 = 8899;

    fn policy() -> ProxyOnlyPolicy {
        ProxyOnlyPolicy::to_proxy(PROXY)
    }

    fn to(port: u16, is_loopback: bool) -> Destination {
        Destination { port, is_loopback }
    }

    /// The proxy's own port on loopback is the one way out.
    #[test]
    fn the_proxy_is_reachable() {
        assert_eq!(
            policy().decide(NetSyscall::ReachOut, to(PROXY, true)),
            NetVerdict::Allow
        );
    }

    /// The port alone is not the test.
    ///
    /// This is the whole reason loopback is checked. A rule written on the port
    /// number permits reaching any host on that port, and the workload chooses
    /// the port it dials, so "only the proxy's port" would mean "anywhere, as
    /// long as you use this number".
    #[test]
    fn the_proxys_port_on_another_host_is_not_the_proxy() {
        assert_eq!(
            policy().decide(NetSyscall::ReachOut, to(PROXY, false)),
            NetVerdict::Deny
        );
    }

    /// Loopback alone is not the test either.
    #[test]
    fn another_port_on_loopback_is_not_the_proxy() {
        assert_eq!(
            policy().decide(NetSyscall::ReachOut, to(PROXY + 1, true)),
            NetVerdict::Deny
        );
        assert_eq!(
            policy().decide(NetSyscall::ReachOut, to(53, true)),
            NetVerdict::Deny,
            "a resolver on loopback is still not the proxy"
        );
    }

    /// Binding is refused unless the policy named the port: a governed workload
    /// is not a server by default.
    #[test]
    fn binding_needs_an_explicit_grant() {
        assert_eq!(
            policy().decide(NetSyscall::Bind, to(3000, false)),
            NetVerdict::Deny
        );

        let serving = ProxyOnlyPolicy {
            proxy_port: PROXY,
            bind_ports: vec![3000],
            bind_port_ranges: vec![(9000, 9010)],
        };
        assert_eq!(
            serving.decide(NetSyscall::Bind, to(3000, false)),
            NetVerdict::Allow
        );
        for port in [9000, 9005, 9010] {
            assert_eq!(
                serving.decide(NetSyscall::Bind, to(port, false)),
                NetVerdict::Allow,
                "a range is inclusive at both ends, and {port} is inside it"
            );
        }
        assert_eq!(
            serving.decide(NetSyscall::Bind, to(9011, false)),
            NetVerdict::Deny
        );
        assert_eq!(
            serving.decide(NetSyscall::Bind, to(8999, false)),
            NetVerdict::Deny
        );
    }

    /// A bind grant is not an egress grant.
    ///
    /// They are different acts on different ports, and a policy that let a
    /// listening port double as a way out would be granting egress nobody
    /// wrote.
    #[test]
    fn a_bind_grant_does_not_open_a_way_out() {
        let serving = ProxyOnlyPolicy {
            proxy_port: PROXY,
            bind_ports: vec![3000],
            bind_port_ranges: Vec::new(),
        };
        assert_eq!(
            serving.decide(NetSyscall::ReachOut, to(3000, true)),
            NetVerdict::Deny
        );
        assert_eq!(
            serving.decide(NetSyscall::ReachOut, to(3000, false)),
            NetVerdict::Deny
        );
    }

    /// A policy nobody filled in lets nothing out.
    ///
    /// Without the zero check, a default-constructed policy would match a
    /// connect to port 0 and allow it — a way out opened by forgetting to fill
    /// a field in, which is the worst way for one to appear.
    #[test]
    fn a_default_policy_lets_nothing_out() {
        let empty = ProxyOnlyPolicy::default();
        for destination in [to(0, true), to(0, false), to(80, true)] {
            assert_eq!(
                empty.decide(NetSyscall::ReachOut, destination),
                NetVerdict::Deny,
                "a policy with no proxy port must not be a way out to {destination:?}"
            );
        }
        assert_eq!(
            empty.decide(NetSyscall::Bind, to(0, false)),
            NetVerdict::Deny
        );
    }
}
