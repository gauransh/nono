//! A filesystem capability vocabulary with one word per operation.
//!
//! [`AccessMode`][crate::AccessMode] has three values, and every one of them is
//! a bundle. `Read` on Linux is `READ_FILE | READ_DIR | EXECUTE`; `Write` is
//! eleven rights including `REFER` and `TRUNCATE`, because atomic writes need
//! them. Those bundles are honestly documented, but a caller who wants "this
//! program may append to the log and nothing else" cannot say so, and a caller
//! who says `Write` cannot find out that they also said "may rename anything in
//! this tree".
//!
//! [`FsModeSet`] is the vocabulary that lets them say it: thirteen named modes,
//! granted per path through
//! [`CapabilitySet::allow_path_modes`][crate::CapabilitySet::allow_path_modes].
//! [`AccessMode`][crate::AccessMode] and
//! [`allow_path`][crate::CapabilitySet::allow_path] are unchanged and still
//! mean exactly what they meant; [`FsModeSet::describes_access_mode`] states
//! what that is in this vocabulary's own words.
//!
//! # Honesty is the point, not granularity
//!
//! Neither platform can enforce all thirteen modes separately, and the two fall
//! short in *different* places. Landlock cannot restrict `stat(2)` at all;
//! Seatbelt can. Landlock has a distinct `TRUNCATE` right; Seatbelt folds
//! truncation into `file-write-data`. Compiling a mode set therefore does not
//! return a bag of rights — it returns a [`CompiledModes`] that says, for every
//! mode the caller named:
//!
//! - [`enforced`][CompiledModes::enforced] — the platform grants exactly this;
//! - [`bundled`][CompiledModes::bundled] — a mode the caller did **not** ask
//!   for that the grant confers anyway, with the mode that dragged it in and
//!   the reason;
//! - [`always_allowed`][CompiledModes::always_allowed] — the platform cannot
//!   restrict this operation at all, so the grant is a no-op and saying
//!   otherwise would be a lie;
//! - [`refused`][CompiledModes::refused] — the platform cannot express it here,
//!   so the whole grant fails closed rather than quietly becoming something
//!   else;
//! - [`delegated`][CompiledModes::delegated] — enforced, but by a different
//!   capability in this library rather than by the filesystem rule set.
//!
//! Nothing is dropped and nothing is widened without an entry naming it. A
//! refusal is an error at prepare/apply time, not a warning.
//!
//! # Where the mapping logic lives
//!
//! [`landlock_map`] and [`sbpl_map`] are compiled on **every** platform and
//! take the platform's capabilities as data — [`landlock_map`] takes a
//! [`LandlockRightsAvailable`][landlock_map::LandlockRightsAvailable] rather
//! than reading the kernel. That is deliberate: the Linux mapping, including
//! every ABI gate, is unit-testable on a macOS host, months before a Linux
//! runner exists. The thin adapters that read the real
//! `DetectedAbi` (Linux-only) and emit real rules live in
//! `crate::sandbox`.

pub mod landlock_map;
pub mod sbpl_map;

use crate::capability::{AccessMode, CapabilitySource, resolve_directory, resolve_file};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

/// One filesystem operation a grant can name.
///
/// Twelve of these are leaves — a single operation the contract distinguishes.
/// The thirteenth, [`FsMode::AtomicWrite`], is a *named bundle*: it expands to
/// a fixed, published set of leaves ([`FsMode::expands_to`]) and has no
/// enforcement of its own. It exists because "write a temp file, rename it over
/// the target, remove the leftover" is what real tools do, and spelling it out
/// four times at every call site is how a caller ends up granting the wrong
/// three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsMode {
    /// Read the bytes of a file. Linux `READ_FILE`; macOS `file-read-data`.
    ReadContents,
    /// List a directory. Linux `READ_DIR`; macOS `file-read-data` on the
    /// directory, which is the same operation Seatbelt checks for `readdir`.
    ReadDir,
    /// `stat(2)` and friends. **Landlock has no right for this**, so on Linux
    /// the grant is always-allowed rather than enforced; Seatbelt has
    /// `file-read-metadata` and really does restrict it.
    ReadMetadata,
    /// Write bytes into an existing file. Linux `WRITE_FILE`; macOS
    /// `file-write-data`.
    Write,
    /// Write bytes at the end of an existing file. Neither platform has an
    /// append-only right, so this cannot be separated from [`FsMode::Write`];
    /// both bundle, and both say so.
    Append,
    /// Create a **regular** file. Linux `MAKE_REG` *only* — see the type
    /// documentation below for what that deliberately excludes. macOS
    /// `file-write-create`, which cannot be narrowed to regular files.
    Create,
    /// Shorten a file. Linux `TRUNCATE`, which needs ABI V3; on an older kernel
    /// the grant is **refused**, because there truncation is not restrictable
    /// at all and a silent no-op would read as enforcement. macOS folds it into
    /// `file-write-data`.
    Truncate,
    /// `unlink(2)` a file. Linux `REMOVE_FILE`; macOS `file-write-unlink`,
    /// which cannot be separated from [`FsMode::RemoveDir`].
    RemoveFile,
    /// `rmdir(2)` a directory. Linux `REMOVE_DIR`; macOS `file-write-unlink`.
    RemoveDir,
    /// `rename(2)` and `link(2)`, including across directories. Linux `REFER`,
    /// which needs ABI V2; on V1 the grant is **refused**. macOS has no rename
    /// operation — it is the `file-write-create` + `file-write-unlink` pair,
    /// and the composition is disclosed.
    Rename,
    /// `execve(2)` the path. Linux `EXECUTE`; macOS `process-exec*` **scoped to
    /// the path**, which is the whole reason this mode exists.
    Execute,
    /// `connect(2)` to a pathname `AF_UNIX` socket.
    ///
    /// This library already models socket grants as
    /// [`UnixSocketCapability`][crate::UnixSocketCapability], with its own
    /// scope, its own bind/connect split and its own enforcement on both
    /// platforms. This mode does not reimplement any of it: naming it in a mode
    /// set registers a real `UnixSocketCapability` through the existing
    /// constructor, and the compile result reports it as
    /// [`delegated`][CompiledModes::delegated] rather than pretending a
    /// filesystem rule enforced it.
    UnixSocketConnect,
    /// The create-write-rename-unlink cluster a temp-file write needs.
    ///
    /// A named bundle over [`FsMode::Create`], [`FsMode::Write`],
    /// [`FsMode::Rename`] and [`FsMode::RemoveFile`] — see
    /// [`FsMode::expands_to`]. Not magic: the expansion is a published constant,
    /// every member it adds beyond what the caller named is reported in
    /// [`CompiledModes::bundled`], and a member the platform cannot express
    /// refuses the whole grant (on Landlock V1 that is `Rename`, so
    /// `AtomicWrite` refuses there).
    AtomicWrite,
}

impl FsMode {
    /// Every mode, in a fixed order that the report tables and the docs share.
    pub const ALL: [FsMode; 13] = [
        FsMode::ReadContents,
        FsMode::ReadDir,
        FsMode::ReadMetadata,
        FsMode::Write,
        FsMode::Append,
        FsMode::Create,
        FsMode::Truncate,
        FsMode::RemoveFile,
        FsMode::RemoveDir,
        FsMode::Rename,
        FsMode::Execute,
        FsMode::UnixSocketConnect,
        FsMode::AtomicWrite,
    ];

    /// What [`FsMode::AtomicWrite`] stands for: `Create` the temp file, `Write`
    /// its contents, `Rename` it over the target, `RemoveFile` the leftover
    /// when the rename never happens.
    ///
    /// Deliberately **not** including [`FsMode::Truncate`]: an atomic write
    /// never shortens anything, it replaces. A caller who also wants in-place
    /// truncation has to say so, which is the point of the vocabulary.
    pub const ATOMIC_WRITE_MEMBERS: [FsMode; 4] = [
        FsMode::Create,
        FsMode::Write,
        FsMode::Rename,
        FsMode::RemoveFile,
    ];

    /// The stable snake_case name, identical to the serde representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FsMode::ReadContents => "read_contents",
            FsMode::ReadDir => "read_dir",
            FsMode::ReadMetadata => "read_metadata",
            FsMode::Write => "write",
            FsMode::Append => "append",
            FsMode::Create => "create",
            FsMode::Truncate => "truncate",
            FsMode::RemoveFile => "remove_file",
            FsMode::RemoveDir => "remove_dir",
            FsMode::Rename => "rename",
            FsMode::Execute => "execute",
            FsMode::UnixSocketConnect => "unix_socket_connect",
            FsMode::AtomicWrite => "atomic_write",
        }
    }

    /// The leaves this mode is a name for, or an empty slice when it is itself
    /// a leaf.
    #[must_use]
    pub fn expands_to(self) -> &'static [FsMode] {
        match self {
            FsMode::AtomicWrite => &Self::ATOMIC_WRITE_MEMBERS,
            _ => &[],
        }
    }

    /// Position in [`FsMode::ALL`], which is also this mode's bit in
    /// [`FsModeSet`].
    fn bit(self) -> u16 {
        let index = match self {
            FsMode::ReadContents => 0,
            FsMode::ReadDir => 1,
            FsMode::ReadMetadata => 2,
            FsMode::Write => 3,
            FsMode::Append => 4,
            FsMode::Create => 5,
            FsMode::Truncate => 6,
            FsMode::RemoveFile => 7,
            FsMode::RemoveDir => 8,
            FsMode::Rename => 9,
            FsMode::Execute => 10,
            FsMode::UnixSocketConnect => 11,
            FsMode::AtomicWrite => 12,
        };
        1u16 << index
    }
}

impl std::fmt::Display for FsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A set of [`FsMode`]s. Order-independent, duplicate-free, `Copy`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct FsModeSet(u16);

impl FsModeSet {
    /// The empty set. A grant of nothing is legal and grants nothing; the
    /// builder refuses it, because an empty grant is always a mistake at a call
    /// site rather than an intention.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// A set built from a slice, for the common `FsModeSet::of(&[…])` call.
    #[must_use]
    pub fn of(modes: &[FsMode]) -> Self {
        let mut set = Self::empty();
        for mode in modes {
            set.insert(*mode);
        }
        set
    }

    /// This set plus `mode` (builder form).
    #[must_use]
    pub fn with(mut self, mode: FsMode) -> Self {
        self.insert(mode);
        self
    }

    /// Add `mode` in place.
    pub fn insert(&mut self, mode: FsMode) {
        self.0 |= mode.bit();
    }

    /// Whether `mode` is in this set.
    #[must_use]
    pub fn contains(self, mode: FsMode) -> bool {
        self.0 & mode.bit() != 0
    }

    /// Whether this set names nothing.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The union of two sets.
    #[must_use]
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The modes in this set, in [`FsMode::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = FsMode> {
        FsMode::ALL
            .into_iter()
            .filter(move |mode| self.contains(*mode))
    }

    /// How many modes this set names.
    #[must_use]
    pub fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// What the coarse [`AccessMode`] grants mean in this vocabulary.
    ///
    /// [`allow_path`][crate::CapabilitySet::allow_path] is unchanged and is
    /// still the right call for a broad grant; this function is how that
    /// grant's meaning is *stated* rather than left to be read out of
    /// `access_to_landlock` and `generate_profile`.
    ///
    /// One residual is deliberately **not** representable and is named instead:
    /// on Linux, coarse `Write` also grants `MAKE_CHAR`, `MAKE_DIR`,
    /// `MAKE_SOCK`, `MAKE_FIFO`, `MAKE_BLOCK` and `MAKE_SYM`, and this
    /// vocabulary has no mode for creating a non-regular node. So coarse
    /// `Write` is *wider* on Linux than the set returned here, and a caller who
    /// needs `mkdir` inside a sandbox must still use `allow_path`. Stated so
    /// that nobody reads the returned set as an equivalence.
    #[must_use]
    pub fn describes_access_mode(access: AccessMode) -> Self {
        let read = Self::of(&[
            FsMode::ReadContents,
            FsMode::ReadDir,
            FsMode::ReadMetadata,
            FsMode::Execute,
        ]);
        let write = Self::of(&[
            FsMode::Write,
            FsMode::Append,
            FsMode::Create,
            FsMode::Truncate,
            FsMode::RemoveFile,
            FsMode::RemoveDir,
            FsMode::Rename,
        ]);
        match access {
            AccessMode::Read => read,
            AccessMode::Write => write,
            AccessMode::ReadWrite => read.union(write),
        }
    }
}

impl std::fmt::Display for FsModeSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.iter().map(FsMode::as_str).collect();
        write!(f, "{{{}}}", names.join(", "))
    }
}

/// A path grant expressed in [`FsMode`]s.
///
/// The path half is identical to [`FsCapability`][crate::FsCapability] — same
/// canonicalisation, same TOCTOU-safe order, same `original`/`resolved` pair so
/// macOS can emit both spellings of a symlinked path. Only the access half
/// differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsModeCapability {
    /// The path as the caller wrote it, before canonicalisation.
    pub original: PathBuf,
    /// The canonical absolute path.
    pub resolved: PathBuf,
    /// The modes granted on it.
    pub modes: FsModeSet,
    /// True for a single file, false for a directory (recursive).
    pub is_file: bool,
    /// Where this grant came from.
    pub source: CapabilitySource,
}

impl FsModeCapability {
    /// Grant `modes` on a directory, recursively.
    ///
    /// Canonicalises first and checks the type on the resolved path, so there
    /// is no window between "it exists" and "it is a directory".
    pub fn new_dir(path: impl AsRef<Path>, modes: FsModeSet) -> Result<Self> {
        let path = path.as_ref();
        let resolved = resolve_directory(path)?;
        Ok(Self {
            original: path.to_path_buf(),
            resolved,
            modes,
            is_file: false,
            source: CapabilitySource::User,
        })
    }

    /// Grant `modes` on a single file.
    pub fn new_file(path: impl AsRef<Path>, modes: FsModeSet) -> Result<Self> {
        let path = path.as_ref();
        let resolved = resolve_file(path)?;
        Ok(Self {
            original: path.to_path_buf(),
            resolved,
            modes,
            is_file: true,
            source: CapabilitySource::User,
        })
    }
}

impl std::fmt::Display for FsModeCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.resolved.display(), self.modes)
    }
}

/// Which platform a mode set is being compiled for.
///
/// A parameter rather than a `cfg`, so that the Linux mapping is exercised by
/// the test suite on a macOS host and vice versa. The compilers themselves read
/// nothing about the machine they run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeTarget {
    /// Landlock LSM.
    Landlock,
    /// Seatbelt / SBPL.
    Seatbelt,
}

/// Why a grant confers a mode the caller did not ask for.
///
/// Every variant is a property of the platform, not of this library: each one
/// names an operation the kernel's own vocabulary cannot tell apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleReason {
    /// Landlock's `WRITE_FILE` and Seatbelt's `file-write-data` both cover an
    /// `O_APPEND` write. Neither platform has an append-only right, so an
    /// append grant *is* a write grant.
    AppendImpliesWrite,
    /// [`FsMode::AtomicWrite`] is a name for its members
    /// ([`FsMode::ATOMIC_WRITE_MEMBERS`]).
    AtomicWriteCluster,
    /// Seatbelt has no truncate operation; `ftruncate(2)` and `O_TRUNC` are
    /// checked as `file-write-data`.
    SeatbeltTruncateIsWriteData,
    /// Seatbelt has no rename operation; `rename(2)` is checked as
    /// `file-write-create` on the destination and `file-write-unlink` on the
    /// source.
    SeatbeltRenameIsCreatePlusUnlink,
    /// Seatbelt's `file-write-unlink` covers `unlink(2)` and `rmdir(2)` alike.
    SeatbeltUnlinkCoversFilesAndDirectories,
    /// Seatbelt's `file-read-data` is what both `read(2)` on a file and
    /// `readdir(3)` on a directory are checked against.
    SeatbeltReadDataCoversFilesAndDirectories,
}

impl BundleReason {
    /// One sentence a human can check, for diagnostics and documentation.
    #[must_use]
    pub fn explain(self) -> &'static str {
        match self {
            BundleReason::AppendImpliesWrite => {
                "neither Landlock nor Seatbelt has an append-only right; an append grant \
                 compiles to the same write right as a write grant"
            }
            BundleReason::AtomicWriteCluster => {
                "atomic_write is a published name for create + write + rename + remove_file"
            }
            BundleReason::SeatbeltTruncateIsWriteData => {
                "Seatbelt has no truncate operation; truncation is checked as file-write-data"
            }
            BundleReason::SeatbeltRenameIsCreatePlusUnlink => {
                "Seatbelt has no rename operation; rename is checked as file-write-create on \
                 the destination and file-write-unlink on the source"
            }
            BundleReason::SeatbeltUnlinkCoversFilesAndDirectories => {
                "Seatbelt's file-write-unlink covers unlink(2) and rmdir(2) alike"
            }
            BundleReason::SeatbeltReadDataCoversFilesAndDirectories => {
                "Seatbelt's file-read-data is what both read(2) on a file and readdir(3) on a \
                 directory are checked against"
            }
        }
    }
}

/// A mode the caller did not ask for that the grant confers anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModeBundle {
    /// The mode the caller *did* ask for.
    pub requested: FsMode,
    /// The mode that rides along with it.
    pub also_granted: FsMode,
    /// Why the platform cannot separate them.
    pub why: BundleReason,
}

/// Why the platform will not express a mode, so the grant fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RefusalReason {
    /// The Landlock access right this mode needs is not carried by the detected
    /// ABI. Refused rather than dropped: on those kernels the operation is not
    /// restrictable at all, so a grant that silently compiled to nothing would
    /// read as enforcement.
    UnsupportedRight {
        /// The right that is missing.
        right: landlock_map::LandlockRightName,
        /// The ABI version actually detected.
        abi: u8,
        /// The ABI version that first carries the right.
        needed_abi: u8,
    },
    /// The Landlock access right this mode needs may not appear in a rule whose
    /// path is not a directory. Refused rather than dropped for the same reason
    /// as above: the kernel refuses such a rule outright, and `rust-landlock`
    /// masks the offending rights instead — so a grant that compiled to a
    /// silently emptied rule would read as enforcement.
    DirectoryOnlyRightOnFile {
        /// The right that only a directory rule may carry.
        right: landlock_map::LandlockRightName,
    },
}

impl std::fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefusalReason::UnsupportedRight {
                right,
                abi,
                needed_abi,
            } => write!(
                f,
                "Landlock ABI V{abi} does not carry {right}, which first appears in V{needed_abi}; \
                 on this kernel the operation cannot be restricted at all, so the grant is \
                 refused rather than compiled to a rule that would enforce nothing"
            ),
            RefusalReason::DirectoryOnlyRightOnFile { right } => write!(
                f,
                "Landlock will not carry {right} in a rule on a path that is not a directory: the \
                 kernel accepts only EXECUTE, WRITE_FILE, READ_FILE, TRUNCATE and IOCTL_DEV there \
                 and refuses anything else with EINVAL, so the grant is refused rather than \
                 compiled to a rule the kernel would reject or a library would silently empty"
            ),
        }
    }
}

/// A mode the platform will not express here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModeRefusal {
    /// The mode that cannot be honoured.
    pub mode: FsMode,
    /// Why not.
    pub why: RefusalReason,
}

/// Why a grant is a no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlwaysAllowedReason {
    /// Landlock has no access right covering `stat(2)`, `fstatat(2)`,
    /// `statx(2)` or `access(2)`. A landlocked process can always read metadata
    /// for any path it can name; there is no rule that would change that.
    LandlockCannotRestrictMetadata,
}

impl AlwaysAllowedReason {
    /// One sentence a human can check.
    #[must_use]
    pub fn explain(self) -> &'static str {
        match self {
            AlwaysAllowedReason::LandlockCannotRestrictMetadata => {
                "Landlock has no access right covering stat(2)/statx(2)/access(2): a landlocked \
                 process can always read metadata for any path it can name, so granting \
                 read_metadata changes nothing"
            }
        }
    }
}

/// A mode the platform cannot restrict at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModeAlwaysAllowed {
    /// The mode whose grant is a no-op.
    pub mode: FsMode,
    /// Why it is a no-op.
    pub why: AlwaysAllowedReason,
}

/// Which other mechanism in this library enforces a delegated mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationTarget {
    /// [`UnixSocketCapability`][crate::UnixSocketCapability], registered by
    /// [`CapabilitySet::allow_path_modes`][crate::CapabilitySet::allow_path_modes]
    /// through the same constructor
    /// [`allow_unix_socket`][crate::CapabilitySet::allow_unix_socket] uses.
    UnixSocketCapability,
}

impl DelegationTarget {
    /// What actually enforces the mode, per platform, in one sentence.
    #[must_use]
    pub fn explain(self, target: ModeTarget) -> &'static str {
        match (self, target) {
            (DelegationTarget::UnixSocketCapability, ModeTarget::Seatbelt) => {
                "enforced by the UnixSocketCapability's own Seatbelt rules \
                 ((allow network-outbound (path …))), not by a filesystem rule"
            }
            (DelegationTarget::UnixSocketCapability, ModeTarget::Landlock) => {
                "Landlock has no AF_UNIX connect right; the grant is carried by the \
                 UnixSocketCapability and enforced only where the seccomp-notify AF_UNIX \
                 mediation is installed"
            }
        }
    }
}

/// A mode enforced by another capability rather than by the filesystem rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModeDelegation {
    /// The delegated mode.
    pub mode: FsMode,
    /// What enforces it instead.
    pub target: DelegationTarget,
}

/// What a platform will actually do with a requested [`FsModeSet`].
///
/// The four honest outcomes plus one: `delegated` is a documented addition to
/// the `{enforced, bundled, always_allowed, refused}` shape, because a mode
/// that *is* enforced — by a sibling capability in this same library — is none
/// of the other four, and folding it into any of them would be exactly the kind
/// of rounding this type exists to prevent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompiledModes {
    enforced: Vec<FsMode>,
    bundled: Vec<ModeBundle>,
    always_allowed: Vec<ModeAlwaysAllowed>,
    refused: Vec<ModeRefusal>,
    delegated: Vec<ModeDelegation>,
}

impl CompiledModes {
    /// Modes the platform grants as asked.
    #[must_use]
    pub fn enforced(&self) -> &[FsMode] {
        &self.enforced
    }

    /// Modes the caller did not ask for that the grant confers anyway.
    #[must_use]
    pub fn bundled(&self) -> &[ModeBundle] {
        &self.bundled
    }

    /// Modes whose grant is a no-op because the platform cannot restrict them.
    #[must_use]
    pub fn always_allowed(&self) -> &[ModeAlwaysAllowed] {
        &self.always_allowed
    }

    /// Modes the platform will not express, which make the grant fail closed.
    #[must_use]
    pub fn refused(&self) -> &[ModeRefusal] {
        &self.refused
    }

    /// Modes enforced by a sibling capability rather than by filesystem rules.
    #[must_use]
    pub fn delegated(&self) -> &[ModeDelegation] {
        &self.delegated
    }

    /// The first refusal, if any. A caller that is about to apply a policy
    /// checks this and fails; there is no partial-apply path.
    #[must_use]
    pub fn first_refusal(&self) -> Option<&ModeRefusal> {
        self.refused.first()
    }

    /// Whether `mode` will be conferred, whether asked for or bundled in.
    #[must_use]
    pub fn grants(&self, mode: FsMode) -> bool {
        self.enforced.contains(&mode)
            || self.bundled.iter().any(|entry| entry.also_granted == mode)
            || self.delegated.iter().any(|entry| entry.mode == mode)
    }

    /// The bundle entry that discloses `also_granted`, if there is one.
    #[must_use]
    pub fn bundle_for(&self, also_granted: FsMode) -> Option<&ModeBundle> {
        self.bundled
            .iter()
            .find(|entry| entry.also_granted == also_granted)
    }
}

/// How enforceable one mode is on one platform.
///
/// The vocabulary a support report answers in: five outcomes from the contract
/// plus [`ModeEnforceability::Delegated`], for the one mode this library
/// enforces through a different capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "enforceability", rename_all = "snake_case")]
pub enum ModeEnforceability {
    /// The platform expresses this mode as a grant distinct from the others.
    Enforceable,
    /// The platform cannot separate it from another mode, so granting either
    /// grants both.
    BundledWith {
        /// The mode it cannot be separated from.
        mode: FsMode,
    },
    /// The platform cannot restrict the operation at all. A grant is a no-op
    /// and the absence of a grant is not a denial.
    Unrestrictable,
    /// The platform could express it, but not at the version detected here.
    NeedsAbi {
        /// The first ABI version that carries the right.
        abi: u8,
    },
    /// The platform has no mechanism for it.
    Unsupported,
    /// Enforced, but by a sibling capability rather than by the filesystem
    /// rules — see [`DelegationTarget`].
    Delegated {
        /// What enforces it.
        target: DelegationTarget,
    },
}

/// Compile `requested` for `target`, given whatever the platform can do.
///
/// The shared half of both platform mappings: bundle closure, the always-allowed
/// and delegated classifications, and the refusal check. The platform-specific
/// halves ([`landlock_map`], [`sbpl_map`]) supply the implication table and turn
/// the resulting mode set into rights or SBPL operations.
pub(crate) fn compile_common(
    requested: FsModeSet,
    target: ModeTarget,
    implications: fn(FsMode, ModeTarget) -> &'static [(FsMode, BundleReason)],
    refuse: impl Fn(FsMode) -> Option<RefusalReason>,
) -> (CompiledModes, FsModeSet) {
    let mut compiled = CompiledModes::default();
    let mut granted = requested;
    let mut disclosed = FsModeSet::empty();

    // Breadth-first from each requested mode so that the mode named in a
    // bundle entry is the one the caller actually wrote, not an intermediate.
    for root in requested.iter() {
        let mut seen = FsModeSet::empty().with(root);
        let mut queue: VecDeque<FsMode> = VecDeque::new();
        queue.push_back(root);
        while let Some(current) = queue.pop_front() {
            for (implied, why) in implications(current, target) {
                if seen.contains(*implied) {
                    continue;
                }
                seen.insert(*implied);
                queue.push_back(*implied);
                granted.insert(*implied);
                // Only a mode the caller did not name is a disclosure. A caller
                // who asked for both halves of a bundle is not being widened.
                if !requested.contains(*implied) && !disclosed.contains(*implied) {
                    disclosed.insert(*implied);
                    compiled.bundled.push(ModeBundle {
                        requested: root,
                        also_granted: *implied,
                        why: *why,
                    });
                }
            }
        }
    }

    for mode in granted.iter() {
        if let Some(why) = refuse(mode) {
            compiled.refused.push(ModeRefusal { mode, why });
            continue;
        }
        match (mode, target) {
            // A name, not an operation: its members are in `granted` already.
            (FsMode::AtomicWrite, _) => {}
            (FsMode::UnixSocketConnect, _) => compiled.delegated.push(ModeDelegation {
                mode,
                target: DelegationTarget::UnixSocketCapability,
            }),
            (FsMode::ReadMetadata, ModeTarget::Landlock) => {
                compiled.always_allowed.push(ModeAlwaysAllowed {
                    mode,
                    why: AlwaysAllowedReason::LandlockCannotRestrictMetadata,
                });
            }
            _ => {
                // A mode that rode in on a bundle is disclosed there, not
                // claimed here: `enforced` is what the caller asked for and got.
                if requested.contains(mode) {
                    compiled.enforced.push(mode);
                }
            }
        }
    }

    // `AtomicWrite` is a name whose members are all present, so it is granted
    // as asked. Recorded last so it sorts after the members it stands for.
    if requested.contains(FsMode::AtomicWrite) && compiled.refused.is_empty() {
        compiled.enforced.push(FsMode::AtomicWrite);
    }

    (compiled, granted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mode_has_a_distinct_bit_and_a_distinct_name() {
        let mut bits = 0u16;
        let mut names = std::collections::HashSet::new();
        for mode in FsMode::ALL {
            assert_eq!(
                bits & mode.bit(),
                0,
                "{mode} shares a bit with another mode"
            );
            bits |= mode.bit();
            assert!(names.insert(mode.as_str()), "{mode} shares a name");
        }
        assert_eq!(bits.count_ones() as usize, FsMode::ALL.len());
    }

    #[test]
    fn a_set_round_trips_through_iter_in_all_order() {
        let set = FsModeSet::of(&[FsMode::Execute, FsMode::ReadContents, FsMode::Write]);
        let collected: Vec<FsMode> = set.iter().collect();
        assert_eq!(
            collected,
            vec![FsMode::ReadContents, FsMode::Write, FsMode::Execute]
        );
        assert_eq!(set.len(), 3);
        assert!(!set.is_empty());
        assert!(FsModeSet::empty().is_empty());
    }

    #[test]
    fn atomic_write_is_a_published_expansion_not_magic() {
        assert_eq!(
            FsMode::AtomicWrite.expands_to(),
            &[
                FsMode::Create,
                FsMode::Write,
                FsMode::Rename,
                FsMode::RemoveFile
            ]
        );
        // Truncate is deliberately absent: an atomic write replaces, it does
        // not shorten. If this ever changes it has to change here, in the
        // docs, and in both mapping tables at once.
        assert!(!FsMode::AtomicWrite.expands_to().contains(&FsMode::Truncate));
        for mode in FsMode::ALL {
            if mode != FsMode::AtomicWrite {
                assert!(mode.expands_to().is_empty(), "{mode} must be a leaf");
            }
        }
    }

    #[test]
    fn the_coarse_access_modes_are_described_as_the_bundles_they_are() {
        let read = FsModeSet::describes_access_mode(AccessMode::Read);
        assert!(read.contains(FsMode::ReadContents));
        assert!(read.contains(FsMode::ReadDir));
        assert!(read.contains(FsMode::ReadMetadata));
        // The one that surprises people: coarse Read grants EXECUTE on Linux
        // and, on macOS, is what lets a path be exec'd at all.
        assert!(read.contains(FsMode::Execute));
        assert!(!read.contains(FsMode::Write));

        let write = FsModeSet::describes_access_mode(AccessMode::Write);
        for mode in [
            FsMode::Write,
            FsMode::Append,
            FsMode::Create,
            FsMode::Truncate,
            FsMode::RemoveFile,
            FsMode::RemoveDir,
            FsMode::Rename,
        ] {
            assert!(write.contains(mode), "coarse Write must describe {mode}");
        }
        assert!(!write.contains(FsMode::ReadContents));

        assert_eq!(
            FsModeSet::describes_access_mode(AccessMode::ReadWrite),
            read.union(write)
        );
    }

    #[test]
    fn serde_names_are_the_stable_snake_case_ones() -> Result<()> {
        for mode in FsMode::ALL {
            let json = serde_json::to_string(&mode).map_err(|err| {
                crate::error::NonoError::ConfigParse(format!("mode must serialize: {err}"))
            })?;
            assert_eq!(json, format!("\"{}\"", mode.as_str()));
        }
        Ok(())
    }
}
