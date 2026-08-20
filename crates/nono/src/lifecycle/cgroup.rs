//! Containment by cgroup, for runs whose process group is not enough.
//!
//! # Why this exists
//! The lifecycle contains a run by the **process group** its child leads: the
//! stop signals the group, and cleanup proves absence by finding the group
//! empty. A process group is escapable by design — `setsid(2)` is exactly the
//! call that leaves one — so a workload's child can detach, survive the stop,
//! and leave a genuinely empty group behind. Cleanup then reports the run gone
//! while the escaped process is still running. That is DEF-03, and it is a hole
//! in the strongest claim this library makes.
//!
//! A cgroup is the containment a process cannot walk out of: leaving one means
//! writing to another cgroup's `cgroup.procs`, which needs privilege the
//! workload does not have and which the sandbox denies besides. cgroup v2 also
//! offers `cgroup.kill`, which kills every member in a single write — no
//! signalling races, no descendants missed, and no dependence on who is whose
//! child.
//!
//! # What this module is, and is not
//! It is the primitive: create, place, kill, ask whether anything is left.
//! Nothing here changes how the lifecycle contains a run — wiring it in is a
//! change to that model and is done separately, so that the mechanism can be
//! reviewed and tested on its own first.
//!
//! # Availability
//! Linux with a writable cgroup v2 mount, and `cgroup.kill` needs kernel 5.14.
//! Every entry point reports what is missing rather than assuming it is there:
//! a host without this must fall back to the process group knowingly, not
//! silently.

use std::path::{Path, PathBuf};

/// Why a cgroup operation could not be carried out.
///
/// Its own type, like [`PlanError`](super::PlanError) and the rest: a caller
/// deciding whether to fall back to the process group needs to know *which*
/// thing was missing, and a flattened I/O error does not say.
#[derive(Debug, thiserror::Error)]
pub enum CgroupError {
    /// The name was not a single path component, so the cgroup would not have
    /// been where the caller asked for it.
    #[error("cgroup name {name:?} must be a single path component")]
    Name {
        /// The name that was refused.
        name: String,
    },

    /// The directory could not be created, read, written or removed.
    #[error("cgroup {path}: {source}")]
    Io {
        /// The path concerned.
        path: PathBuf,
        /// What the kernel said.
        source: std::io::Error,
    },

    /// This kernel does not offer `cgroup.kill`.
    #[error("{path} has no cgroup.kill; killing a whole cgroup in one write needs kernel 5.14")]
    NoKillFile {
        /// The cgroup that lacks it.
        path: PathBuf,
    },
}

/// Where a cgroup v2 hierarchy is mounted on an ordinary Linux system.
pub const CGROUP2_ROOT: &str = "/sys/fs/cgroup";

/// The file every member pid is written into, and read back from.
const PROCS: &str = "cgroup.procs";
/// The file one write to which kills every member (kernel 5.14+).
const KILL: &str = "cgroup.kill";

/// A cgroup this process created to hold one run.
///
/// Dropping it does **not** kill the members: teardown is a lifecycle decision
/// with its own ordering, and a `Drop` that killed a workload because a value
/// went out of scope would be a surprise in the worst possible place. Use
/// [`Self::kill_all`] and then [`Self::remove`].
#[derive(Debug)]
pub struct RunCgroup {
    path: PathBuf,
}

impl RunCgroup {
    /// Create a cgroup named `name` under `parent`.
    ///
    /// # Errors
    ///
    /// [`CgroupError`] if the directory cannot be created — most often because
    /// the mount is read-only or this process lacks the privilege, which is the
    /// ordinary case inside an unprivileged container.
    pub fn create(parent: &Path, name: &str) -> Result<Self, CgroupError> {
        // A name with a separator in it would place the cgroup somewhere the
        // caller did not ask for, and `..` would place it outside the parent
        // entirely. Refused rather than sanitised: a caller that produced such
        // a name has a bug worth seeing.
        if name.is_empty() || name.contains('/') || name.contains("..") {
            return Err(CgroupError::Name {
                name: name.to_owned(),
            });
        }
        let path = parent.join(name);
        std::fs::create_dir_all(&path).map_err(|source| CgroupError::Io {
            path: path.clone(),
            source,
        })?;
        Ok(Self { path })
    }

    /// The directory backing this cgroup.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this kernel supports killing the whole cgroup in one write.
    #[must_use]
    pub fn supports_kill(&self) -> bool {
        self.path.join(KILL).is_file()
    }

    /// Move `pid` into this cgroup.
    ///
    /// The process is contained from the moment this returns, including every
    /// descendant it later starts: cgroup membership is inherited across `fork`
    /// and survives `setsid`.
    ///
    /// # Errors
    ///
    /// [`CgroupError`] if the write is refused.
    pub fn place(&self, pid: i32) -> Result<(), CgroupError> {
        let procs = self.path.join(PROCS);
        std::fs::write(&procs, pid.to_string()).map_err(|source| CgroupError::Io {
            path: procs,
            source,
        })
    }

    /// Kill every process in this cgroup, in one write.
    ///
    /// Unlike signalling a process group this cannot miss a member: there is no
    /// set to enumerate and nothing that can leave between the enumeration and
    /// the signal.
    ///
    /// # Errors
    ///
    /// [`CgroupError`] if the kernel does not offer `cgroup.kill` or the write is
    /// refused. A caller that gets this must fall back deliberately rather than
    /// treat the run as contained.
    pub fn kill_all(&self) -> Result<(), CgroupError> {
        let kill = self.path.join(KILL);
        if !kill.is_file() {
            return Err(CgroupError::NoKillFile {
                path: self.path.clone(),
            });
        }
        std::fs::write(&kill, "1").map_err(|source| CgroupError::Io { path: kill, source })
    }

    /// The pids currently in this cgroup.
    ///
    /// # Errors
    ///
    /// [`CgroupError`] if `cgroup.procs` cannot be read. An unreadable membership
    /// is not an empty one and must not be reported as absence.
    pub fn members(&self) -> Result<Vec<i32>, CgroupError> {
        let procs = self.path.join(PROCS);
        let text = std::fs::read_to_string(&procs).map_err(|source| CgroupError::Io {
            path: procs,
            source,
        })?;
        Ok(text
            .lines()
            .filter_map(|line| line.trim().parse::<i32>().ok())
            .collect())
    }

    /// Whether nothing remains in this cgroup.
    ///
    /// # Errors
    ///
    /// [`CgroupError`] if the membership cannot be read — see [`Self::members`].
    pub fn is_empty(&self) -> Result<bool, CgroupError> {
        Ok(self.members()?.is_empty())
    }

    /// Remove the cgroup directory.
    ///
    /// Only succeeds once it is empty, which the kernel enforces; a failure
    /// here therefore usually means something is still inside.
    ///
    /// # Errors
    ///
    /// [`CgroupError`] if the directory cannot be removed.
    pub fn remove(self) -> Result<(), CgroupError> {
        std::fs::remove_dir(&self.path).map_err(|source| CgroupError::Io {
            path: self.path,
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name that is not a single component would place the cgroup somewhere
    /// the caller did not name — outside the parent, in the `..` case.
    #[test]
    fn a_name_that_is_not_one_component_is_refused() {
        for name in ["", "a/b", "..", "../escape", "a/../b"] {
            let created = RunCgroup::create(Path::new("/sys/fs/cgroup"), name);
            assert!(
                created.is_err(),
                "the name {name:?} must be refused rather than sanitised"
            );
        }
    }
}
