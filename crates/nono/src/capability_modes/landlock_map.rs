//! [`FsMode`] to Landlock access rights.
//!
//! Compiled on every platform, deliberately. Nothing here reads the kernel: the
//! ABI arrives as a [`LandlockRightsAvailable`] value, so every arm of the
//! mapping — including both ABI gates — is exercised by the unit tests at the
//! bottom of this file on a macOS host, before any Linux runner exists. The
//! adapter that fills a `LandlockRightsAvailable` from the real
//! `DetectedAbi` (Linux-only) and turns [`LandlockRightName`] into
//! `landlock::AccessFs` is in `crate::sandbox::linux`, and is the only part of
//! the Linux mapping that cannot be run here.

use super::{
    BundleReason, CompiledModes, FsMode, FsModeSet, ModeTarget, RefusalReason, compile_common,
};
use serde::{Deserialize, Serialize};

/// A Landlock filesystem access right, named as the kernel names it.
///
/// A neutral echo of `landlock::AccessFs` so this mapping compiles without the
/// Linux-only crate. The one-to-one correspondence is asserted on Linux by
/// `crate::sandbox::linux`'s own tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockRightName {
    /// `LANDLOCK_ACCESS_FS_READ_FILE`.
    ReadFile,
    /// `LANDLOCK_ACCESS_FS_READ_DIR`.
    ReadDir,
    /// `LANDLOCK_ACCESS_FS_WRITE_FILE`.
    WriteFile,
    /// `LANDLOCK_ACCESS_FS_EXECUTE`.
    Execute,
    /// `LANDLOCK_ACCESS_FS_MAKE_REG`.
    MakeReg,
    /// `LANDLOCK_ACCESS_FS_REMOVE_FILE`.
    RemoveFile,
    /// `LANDLOCK_ACCESS_FS_REMOVE_DIR`.
    RemoveDir,
    /// `LANDLOCK_ACCESS_FS_REFER` (ABI V2+).
    Refer,
    /// `LANDLOCK_ACCESS_FS_TRUNCATE` (ABI V3+).
    Truncate,
}

impl LandlockRightName {
    /// The stable snake_case name, identical to the serde representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LandlockRightName::ReadFile => "read_file",
            LandlockRightName::ReadDir => "read_dir",
            LandlockRightName::WriteFile => "write_file",
            LandlockRightName::Execute => "execute",
            LandlockRightName::MakeReg => "make_reg",
            LandlockRightName::RemoveFile => "remove_file",
            LandlockRightName::RemoveDir => "remove_dir",
            LandlockRightName::Refer => "refer",
            LandlockRightName::Truncate => "truncate",
        }
    }

    /// The first Landlock ABI version that carries this right.
    #[must_use]
    pub fn first_abi(self) -> u8 {
        match self {
            LandlockRightName::Refer => 2,
            LandlockRightName::Truncate => 3,
            _ => 1,
        }
    }
}

impl std::fmt::Display for LandlockRightName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which Landlock rights the kernel in front of us carries.
///
/// A value rather than a `cfg`, so the mapping can be driven from a test with a
/// kernel this machine does not have. On Linux it is built from the real
/// detected ABI by `LandlockRightsAvailable::from_abi_version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LandlockRightsAvailable {
    /// The detected ABI version, carried so a refusal can name it.
    abi: u8,
}

impl LandlockRightsAvailable {
    /// The rights a kernel at `abi` carries.
    ///
    /// Version-driven because that is how Landlock itself is versioned: each
    /// ABI is a superset of the last, and `AccessFs::from_all(ABI::Vn)` is the
    /// same monotone table. `crate::sandbox::linux` asserts the two agree.
    #[must_use]
    pub fn from_abi_version(abi: u8) -> Self {
        Self { abi }
    }

    /// The detected ABI version.
    #[must_use]
    pub fn abi(self) -> u8 {
        self.abi
    }

    /// Whether `right` is carried here.
    #[must_use]
    pub fn has(self, right: LandlockRightName) -> bool {
        self.abi >= right.first_abi()
    }
}

/// What compiling an [`FsModeSet`] for Landlock produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledLandlock {
    /// What the platform will and will not do with each mode.
    pub modes: CompiledModes,
    /// The rights to put in the `PathBeneath` rule, sorted and deduplicated.
    /// Empty when every requested mode was always-allowed or delegated — which
    /// is a legal outcome, and a rule for it is deliberately not emitted.
    pub rights: Vec<LandlockRightName>,
}

/// The rights one mode needs, before any ABI gate is applied.
///
/// The whole Landlock half of the contract, in one table:
///
/// | mode | rights |
/// |---|---|
/// | `read_contents` | `READ_FILE` |
/// | `read_dir` | `READ_DIR` |
/// | `read_metadata` | *(none — not restrictable)* |
/// | `write` | `WRITE_FILE` |
/// | `append` | `WRITE_FILE` |
/// | `create` | `MAKE_REG` |
/// | `truncate` | `TRUNCATE` (V3+) |
/// | `remove_file` | `REMOVE_FILE` |
/// | `remove_dir` | `REMOVE_DIR` |
/// | `rename` | `REFER` (V2+) |
/// | `execute` | `EXECUTE` |
/// | `unix_socket_connect` | *(none — delegated)* |
/// | `atomic_write` | *(none of its own — see its members)* |
///
/// `create` is `MAKE_REG` and **only** `MAKE_REG`. Landlock has seven separate
/// make-rights (`MAKE_REG`, `MAKE_DIR`, `MAKE_CHAR`, `MAKE_BLOCK`, `MAKE_SOCK`,
/// `MAKE_FIFO`, `MAKE_SYM`), and coarse [`AccessMode::Write`][crate::AccessMode]
/// grants all seven. Folding all seven into `create` would mean a caller who
/// asked to create a file also got to create a device node and a symlink, which
/// is the kind of widening this vocabulary exists to stop. The other six have no
/// mode: creating a directory or a symlink inside a mode-set grant is **not**
/// permitted, and a caller who needs it uses `allow_path` and takes the whole
/// coarse bundle knowingly.
#[must_use]
pub fn rights_for(mode: FsMode) -> &'static [LandlockRightName] {
    match mode {
        FsMode::ReadContents => &[LandlockRightName::ReadFile],
        FsMode::ReadDir => &[LandlockRightName::ReadDir],
        FsMode::Write | FsMode::Append => &[LandlockRightName::WriteFile],
        FsMode::Create => &[LandlockRightName::MakeReg],
        FsMode::Truncate => &[LandlockRightName::Truncate],
        FsMode::RemoveFile => &[LandlockRightName::RemoveFile],
        FsMode::RemoveDir => &[LandlockRightName::RemoveDir],
        FsMode::Rename => &[LandlockRightName::Refer],
        FsMode::Execute => &[LandlockRightName::Execute],
        // Landlock cannot restrict stat(2); reported as always-allowed.
        FsMode::ReadMetadata
        // No AF_UNIX right exists; reported as delegated.
        | FsMode::UnixSocketConnect
        // A name for its members, which carry their own rights.
        | FsMode::AtomicWrite => &[],
    }
}

/// Modes Landlock cannot tell apart, and why.
pub(super) fn implications(mode: FsMode, target: ModeTarget) -> &'static [(FsMode, BundleReason)] {
    debug_assert!(matches!(target, ModeTarget::Landlock));
    match mode {
        // `WRITE_FILE` covers an O_APPEND write, in both directions: asking for
        // either gets the other.
        FsMode::Write => &[(FsMode::Append, BundleReason::AppendImpliesWrite)],
        FsMode::Append => &[(FsMode::Write, BundleReason::AppendImpliesWrite)],
        FsMode::AtomicWrite => &[
            (FsMode::Create, BundleReason::AtomicWriteCluster),
            (FsMode::Write, BundleReason::AtomicWriteCluster),
            (FsMode::Rename, BundleReason::AtomicWriteCluster),
            (FsMode::RemoveFile, BundleReason::AtomicWriteCluster),
        ],
        _ => &[],
    }
}

/// Compile `requested` against the rights `available` really carries.
///
/// A mode whose right the ABI does not carry is **refused**, never dropped. On
/// those kernels the operation is not restrictable at all — a `truncate` grant
/// on ABI V2 would compile to no rule while `ftruncate(2)` stayed available
/// everywhere — so a grant that quietly compiled to nothing would read as
/// enforcement. The caller gets a [`RefusalReason::UnsupportedRight`] naming the
/// right, the ABI found, and the ABI needed, and the apply path turns it into an
/// error.
#[must_use]
pub fn compile(requested: FsModeSet, available: LandlockRightsAvailable) -> CompiledLandlock {
    let (modes, granted) = compile_common(requested, ModeTarget::Landlock, implications, |mode| {
        rights_for(mode)
            .iter()
            .find(|right| !available.has(**right))
            .map(|right| RefusalReason::UnsupportedRight {
                right: *right,
                abi: available.abi(),
                needed_abi: right.first_abi(),
            })
    });

    // A refused grant has no rights at all. Fail closed means the rule is never
    // built, not that it is built without the part that failed.
    let rights = if modes.refused().is_empty() {
        let mut rights: Vec<LandlockRightName> = granted
            .iter()
            .flat_map(|mode| rights_for(mode).iter().copied())
            .collect();
        rights.sort_unstable();
        rights.dedup();
        rights
    } else {
        Vec::new()
    };

    CompiledLandlock { modes, rights }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_modes::{AlwaysAllowedReason, DelegationTarget};

    /// A kernel with everything, so a test can isolate one mode.
    const V6: LandlockRightsAvailable = LandlockRightsAvailable { abi: 6 };

    fn compile_one(mode: FsMode, abi: u8) -> CompiledLandlock {
        compile(
            FsModeSet::empty().with(mode),
            LandlockRightsAvailable::from_abi_version(abi),
        )
    }

    #[test]
    fn every_leaf_mode_maps_to_the_right_the_contract_names() {
        let table = [
            (FsMode::ReadContents, LandlockRightName::ReadFile),
            (FsMode::ReadDir, LandlockRightName::ReadDir),
            (FsMode::Write, LandlockRightName::WriteFile),
            (FsMode::Append, LandlockRightName::WriteFile),
            (FsMode::Create, LandlockRightName::MakeReg),
            (FsMode::Truncate, LandlockRightName::Truncate),
            (FsMode::RemoveFile, LandlockRightName::RemoveFile),
            (FsMode::RemoveDir, LandlockRightName::RemoveDir),
            (FsMode::Rename, LandlockRightName::Refer),
            (FsMode::Execute, LandlockRightName::Execute),
        ];
        for (mode, right) in table {
            let compiled = compile_one(mode, 6);
            assert!(
                compiled.rights.contains(&right),
                "{mode} must compile to {right}"
            );
            assert!(
                compiled.modes.refused().is_empty(),
                "{mode} must not be refused on V6"
            );
        }
    }

    #[test]
    fn create_grants_make_reg_and_no_other_node_type() {
        let compiled = compile_one(FsMode::Create, 6);
        assert_eq!(compiled.rights, vec![LandlockRightName::MakeReg]);
        // The published decision: a create grant does not confer directory,
        // symlink, socket, fifo, char- or block-device creation. Deleting this
        // assertion is what a silent widening of `create` would look like.
        assert_eq!(compiled.modes.enforced(), &[FsMode::Create]);
        assert!(compiled.modes.bundled().is_empty());
    }

    #[test]
    fn read_metadata_is_a_disclosed_no_op_not_a_grant() {
        let compiled = compile_one(FsMode::ReadMetadata, 6);
        assert!(
            compiled.rights.is_empty(),
            "Landlock has no right for stat(2); compiling one would be an invention"
        );
        assert!(compiled.modes.enforced().is_empty());
        let disclosed = compiled.modes.always_allowed();
        assert_eq!(disclosed.len(), 1);
        assert_eq!(disclosed[0].mode, FsMode::ReadMetadata);
        assert_eq!(
            disclosed[0].why,
            AlwaysAllowedReason::LandlockCannotRestrictMetadata
        );
    }

    #[test]
    fn append_is_disclosed_as_a_write_grant_in_both_directions() {
        let appended = compile_one(FsMode::Append, 6);
        assert_eq!(appended.rights, vec![LandlockRightName::WriteFile]);
        let bundle = match appended.modes.bundle_for(FsMode::Write) {
            Some(bundle) => bundle,
            None => panic!("granting append must disclose that it also grants write"),
        };
        assert_eq!(bundle.requested, FsMode::Append);
        assert_eq!(bundle.why, BundleReason::AppendImpliesWrite);

        let written = compile_one(FsMode::Write, 6);
        let bundle = match written.modes.bundle_for(FsMode::Append) {
            Some(bundle) => bundle,
            None => panic!("granting write must disclose that it also grants append"),
        };
        assert_eq!(bundle.why, BundleReason::AppendImpliesWrite);
    }

    #[test]
    fn asking_for_both_halves_of_a_bundle_discloses_nothing() {
        let compiled = compile(
            FsModeSet::of(&[FsMode::Write, FsMode::Append]),
            LandlockRightsAvailable::from_abi_version(6),
        );
        assert!(
            compiled.modes.bundled().is_empty(),
            "a caller who named both halves is not being widened"
        );
        assert_eq!(
            compiled.modes.enforced(),
            &[FsMode::Write, FsMode::Append][..]
        );
    }

    #[test]
    fn truncate_is_refused_below_abi_v3_rather_than_dropped() {
        for abi in [1u8, 2] {
            let compiled = compile_one(FsMode::Truncate, abi);
            assert_eq!(
                compiled.modes.refused(),
                &[crate::capability_modes::ModeRefusal {
                    mode: FsMode::Truncate,
                    why: RefusalReason::UnsupportedRight {
                        right: LandlockRightName::Truncate,
                        abi,
                        needed_abi: 3,
                    },
                }][..],
                "ABI V{abi} must refuse truncate, not silently grant nothing"
            );
            assert!(
                compiled.rights.is_empty(),
                "a refused grant produces no rule at all"
            );
        }
        assert!(compile_one(FsMode::Truncate, 3).modes.refused().is_empty());
    }

    #[test]
    fn rename_is_refused_below_abi_v2_rather_than_dropped() {
        let compiled = compile_one(FsMode::Rename, 1);
        assert_eq!(
            compiled.modes.refused(),
            &[crate::capability_modes::ModeRefusal {
                mode: FsMode::Rename,
                why: RefusalReason::UnsupportedRight {
                    right: LandlockRightName::Refer,
                    abi: 1,
                    needed_abi: 2,
                },
            }][..]
        );
        assert!(compiled.rights.is_empty());
        assert!(compile_one(FsMode::Rename, 2).modes.refused().is_empty());
    }

    #[test]
    fn atomic_write_expands_to_its_members_and_discloses_each() {
        let compiled = compile_one(FsMode::AtomicWrite, 6);
        assert_eq!(
            compiled.rights,
            vec![
                LandlockRightName::WriteFile,
                LandlockRightName::MakeReg,
                LandlockRightName::RemoveFile,
                LandlockRightName::Refer,
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
        );
        for member in FsMode::ATOMIC_WRITE_MEMBERS {
            let bundle = match compiled.modes.bundle_for(member) {
                Some(bundle) => bundle,
                None => panic!("atomic_write must disclose that it grants {member}"),
            };
            assert_eq!(bundle.requested, FsMode::AtomicWrite);
            assert_eq!(bundle.why, BundleReason::AtomicWriteCluster);
        }
        // Append rides in transitively through Write, and is disclosed too.
        assert!(compiled.modes.grants(FsMode::Append));
        assert!(!compiled.modes.grants(FsMode::Truncate));
    }

    #[test]
    fn atomic_write_fails_closed_on_a_kernel_without_refer() {
        let compiled = compile_one(FsMode::AtomicWrite, 1);
        assert_eq!(compiled.modes.refused().len(), 1);
        assert_eq!(compiled.modes.refused()[0].mode, FsMode::Rename);
        assert!(
            compiled.rights.is_empty(),
            "an atomic-write grant that cannot rename is not an atomic-write grant"
        );
    }

    #[test]
    fn unix_socket_connect_is_delegated_not_compiled_into_a_path_rule() {
        let compiled = compile_one(FsMode::UnixSocketConnect, 6);
        assert!(compiled.rights.is_empty());
        assert!(compiled.modes.enforced().is_empty());
        assert_eq!(
            compiled.modes.delegated(),
            &[crate::capability_modes::ModeDelegation {
                mode: FsMode::UnixSocketConnect,
                target: DelegationTarget::UnixSocketCapability,
            }][..]
        );
    }

    #[test]
    fn the_full_vocabulary_on_v6_refuses_nothing_and_invents_nothing() {
        let all = FsModeSet::of(&FsMode::ALL);
        let compiled = compile(all, V6);
        assert!(compiled.modes.refused().is_empty());
        // Every right in the table, and nothing that is not in the table.
        let expected: std::collections::BTreeSet<LandlockRightName> = FsMode::ALL
            .iter()
            .flat_map(|mode| rights_for(*mode).iter().copied())
            .collect();
        assert_eq!(
            compiled
                .rights
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<LandlockRightName>>(),
            expected
        );
    }
}
