//! Servicing a seccomp-notify listener for proxy-only egress.
//!
//! # Single responsibility
//! Answer the kernel's questions. It reads a trapped syscall's destination,
//! asks [`ProxyOnlyPolicy`] what to do, and replies. The rule is not here; the
//! machinery is.
//!
//! # Why an unanswered listener is worse than no listener
//! A `SECCOMP_RET_USER_NOTIF` filter blocks the calling thread until somebody
//! replies. A listener nobody services is therefore not a policy that fails
//! open or shut — it is a workload that hangs on its first network syscall,
//! which tells an operator nothing at all. Everything here is arranged so that
//! every notification gets exactly one answer, including the paths where
//! reading the address failed.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::proxy_only::{NetVerdict, ProxyNotifyStats, ProxyOnlyPolicy};
use super::{
    SYS_BIND, SYS_CONNECT, SYS_SENDMMSG, SYS_SENDMSG, SYS_SENDTO, SockaddrInfo, continue_notif,
    deny_notif, net_syscall_kind, notif_id_valid, read_mmsghdr_dests, read_msghdr_dest,
    read_notif_sockaddr, recv_notif, respond_notif_errno,
};

/// Service `listener` until the child is gone.
///
/// Returns when the listener stops producing notifications, which is what
/// happens when the last process under the filter exits. Errors are not
/// returned: there is nothing a caller could do about a listener whose child
/// has died, and the run's own exit path is what reports that.
pub fn serve(listener: &OwnedFd, policy: &ProxyOnlyPolicy, stats: &Arc<ProxyNotifyStats>) {
    let fd = listener.as_raw_fd();
    loop {
        let Ok(notif) = recv_notif(fd) else {
            // The child is gone, or the listener was closed. Either way there
            // is nothing left to answer.
            return;
        };

        let verdict = verdict_for(&notif, policy);

        // Between the notification arriving and this reply, the calling thread
        // may have been killed and its id reused. Answering a stale id would
        // apply this decision to somebody else's syscall.
        match notif_id_valid(fd, notif.id) {
            Ok(true) => {}
            Ok(false) | Err(_) => continue,
        }

        stats.decided.fetch_add(1, Ordering::Relaxed);
        let answered = match verdict {
            NetVerdict::Allow => continue_notif(fd, notif.id),
            NetVerdict::Deny => {
                stats.denied.fetch_add(1, Ordering::Relaxed);
                respond_notif_errno(fd, notif.id, libc::EACCES)
            }
        };
        if answered.is_err() {
            // The reply failed, so the child is still blocked. A denial is the
            // only answer left that can be attempted, and if that fails too the
            // notification is orphaned along with the child that made it.
            let _ = deny_notif(fd, notif.id);
        }
    }
}

/// What to do with one notification.
///
/// Every path that cannot establish a destination returns [`NetVerdict::Deny`].
/// An address this supervisor could not read is not an address it may allow:
/// the memory belongs to the workload, and a read that failed means the
/// workload changed it or the process is already gone.
fn verdict_for(notif: &super::SeccompNotif, policy: &ProxyOnlyPolicy) -> NetVerdict {
    let Some(kind) = net_syscall_kind(notif.data.nr) else {
        // The filter trapped something the rule does not classify, so the two
        // have drifted apart. That is not a state in which to guess.
        return NetVerdict::Deny;
    };

    let destinations = match notif.data.nr {
        SYS_CONNECT | SYS_BIND => read_one(notif.pid, notif.data.args[1], notif.data.args[2]),
        // A null destination means the socket is already connected, so the
        // `connect` that got it there was mediated and this send adds nothing
        // to decide.
        SYS_SENDTO if notif.data.args[4] == 0 => return NetVerdict::Allow,
        SYS_SENDTO => read_one(notif.pid, notif.data.args[4], notif.data.args[5]),
        SYS_SENDMSG => match read_msghdr_dest(notif.pid, notif.data.args[1]) {
            Ok(Some((pointer, len))) => read_one(notif.pid, pointer, len),
            Ok(None) => return NetVerdict::Allow,
            Err(_) => return NetVerdict::Deny,
        },
        SYS_SENDMMSG => match read_mmsghdr_dests(notif.pid, notif.data.args[1], notif.data.args[2])
        {
            Ok(dests) => {
                let mut found = Vec::new();
                for destination in dests {
                    // `None` is a message with no destination of its own: the
                    // socket is already connected, and that connect was
                    // mediated. It adds nothing to decide.
                    let Some((pointer, len)) = destination else {
                        continue;
                    };
                    match read_notif_sockaddr(notif.pid, pointer, len) {
                        Ok(info) => found.push(info),
                        Err(_) => return NetVerdict::Deny,
                    }
                }
                // A batch in which no message named a destination is a batch on
                // an already-connected socket.
                if found.is_empty() {
                    return NetVerdict::Allow;
                }
                found
            }
            Err(_) => return NetVerdict::Deny,
        },
        _ => return NetVerdict::Deny,
    };

    if destinations.is_empty() {
        return NetVerdict::Deny;
    }

    // Every destination, not the first. `sendmmsg` carries a batch, and one
    // permitted message in it must not carry the rest.
    for destination in &destinations {
        if policy.decide(kind, destination.destination()) == NetVerdict::Deny {
            return NetVerdict::Deny;
        }
    }
    NetVerdict::Allow
}

fn read_one(pid: u32, pointer: u64, len: u64) -> Vec<SockaddrInfo> {
    match read_notif_sockaddr(pid, pointer, len) {
        Ok(info) => vec![info],
        Err(_) => Vec::new(),
    }
}
