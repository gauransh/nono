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

    /// Whether a rule may carry this right only when its path is a directory.
    ///
    /// The kernel's own split, not this library's: `add_rule_path_beneath`
    /// refuses a rule on a non-directory that carries anything outside
    /// `ACCESS_FILE` — `EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE |
    /// IOCTL_DEV` — with `EINVAL`. `rust-landlock` knows this and *masks* the
    /// offending rights instead (`landlock-0.4.5` `src/fs.rs:202` for the set
    /// and `:285-308` for the mask, whose own comment is "Linux would return
    /// EINVAL"), which turns a rule the kernel would have rejected into one
    /// that carries nothing. Both outcomes are dishonest here, so the mapping
    /// refuses before either can happen.
    ///
    /// Matched exhaustively so that a right added to this enum has to be
    /// classified rather than defaulting to "a file may carry it".
    #[must_use]
    pub fn is_directory_only(self) -> bool {
        match self {
            LandlockRightName::ReadFile
            | LandlockRightName::WriteFile
            | LandlockRightName::Execute
            | LandlockRightName::Truncate => false,
            LandlockRightName::ReadDir
            | LandlockRightName::MakeReg
            | LandlockRightName::RemoveFile
            | LandlockRightName::RemoveDir
            | LandlockRightName::Refer => true,
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

/// Compile `requested` against the rights `available` really carries, for a
/// path that is a file (`is_file`) or a directory.
///
/// Two gates, and neither of them drops anything.
///
/// A mode whose right the ABI does not carry is **refused**, never dropped. On
/// those kernels the operation is not restrictable at all — a `truncate` grant
/// on ABI V2 would compile to no rule while `ftruncate(2)` stayed available
/// everywhere — so a grant that quietly compiled to nothing would read as
/// enforcement. The caller gets a [`RefusalReason::UnsupportedRight`] naming the
/// right, the ABI found, and the ABI needed, and the apply path turns it into an
/// error.
///
/// A mode whose right only a directory rule may carry
/// ([`LandlockRightName::is_directory_only`]) is refused the same way when the
/// path is a file, with [`RefusalReason::DirectoryOnlyRightOnFile`]. Without
/// this gate the rule reaches either the kernel, which answers `EINVAL`, or
/// `rust-landlock`'s best-effort mask, which empties the rule and reports a
/// partial compatibility result nobody upstream of here reads — a grant that
/// grants nothing while reading as enforcement.
///
/// The ABI gate is checked first, so a kernel that does not carry the right at
/// all says so rather than blaming the path type.
#[must_use]
pub fn compile(
    requested: FsModeSet,
    available: LandlockRightsAvailable,
    is_file: bool,
) -> CompiledLandlock {
    let (modes, granted) = compile_common(requested, ModeTarget::Landlock, implications, |mode| {
        rights_for(mode).iter().find_map(|right| {
            if !available.has(*right) {
                return Some(RefusalReason::UnsupportedRight {
                    right: *right,
                    abi: available.abi(),
                    needed_abi: right.first_abi(),
                });
            }
            if is_file && right.is_directory_only() {
                return Some(RefusalReason::DirectoryOnlyRightOnFile { right: *right });
            }
            None
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

    /// One mode on a *directory*, which is the shape every other test here
    /// means when it says "a grant".
    fn compile_one(mode: FsMode, abi: u8) -> CompiledLandlock {
        compile(
            FsModeSet::empty().with(mode),
            LandlockRightsAvailable::from_abi_version(abi),
            false,
        )
    }

    /// The same mode on a single file.
    fn compile_one_file(mode: FsMode, abi: u8) -> CompiledLandlock {
        compile(
            FsModeSet::empty().with(mode),
            LandlockRightsAvailable::from_abi_version(abi),
            true,
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
            false,
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
    fn a_directory_only_right_is_refused_on_a_file_rather_than_masked_away() {
        // The kernel refuses a PATH_BENEATH rule on a non-directory carrying
        // any right outside ACCESS_FILE with EINVAL, and rust-landlock masks
        // those rights instead of letting it. Either way the caller's grant
        // stops meaning what it says, so the mapping refuses first.
        let table = [
            (FsMode::ReadDir, LandlockRightName::ReadDir),
            (FsMode::Create, LandlockRightName::MakeReg),
            (FsMode::RemoveFile, LandlockRightName::RemoveFile),
            (FsMode::RemoveDir, LandlockRightName::RemoveDir),
            (FsMode::Rename, LandlockRightName::Refer),
        ];
        for (mode, right) in table {
            let compiled = compile_one_file(mode, 6);
            assert_eq!(
                compiled.modes.refused(),
                &[crate::capability_modes::ModeRefusal {
                    mode,
                    why: RefusalReason::DirectoryOnlyRightOnFile { right },
                }][..],
                "{mode} on a file must be refused by name, not compiled to a rule the kernel \
                 rejects or a library empties"
            );
            assert!(
                compiled.rights.is_empty(),
                "a refused grant produces no rule at all"
            );
            // The positive control: the same mode on a directory is untouched.
            assert!(
                compile_one(mode, 6).modes.refused().is_empty(),
                "{mode} on a directory must still compile"
            );
        }
    }

    #[test]
    fn the_rights_a_file_rule_may_carry_are_still_granted_on_a_file() {
        // The other half of the gate. A refusal that swallowed everything would
        // satisfy the test above and break every file grant this vocabulary
        // exists to make.
        for (mode, right) in [
            (FsMode::ReadContents, LandlockRightName::ReadFile),
            (FsMode::Write, LandlockRightName::WriteFile),
            (FsMode::Append, LandlockRightName::WriteFile),
            (FsMode::Truncate, LandlockRightName::Truncate),
            (FsMode::Execute, LandlockRightName::Execute),
        ] {
            let compiled = compile_one_file(mode, 6);
            assert!(
                compiled.modes.refused().is_empty(),
                "{mode} is legal on a file rule and must not be refused"
            );
            assert!(
                compiled.rights.contains(&right),
                "{mode} on a file must still compile to {right}"
            );
        }
        // And the two that carry no right at all are unaffected by the path
        // type, because they never reach a rule.
        for mode in [FsMode::ReadMetadata, FsMode::UnixSocketConnect] {
            assert!(compile_one_file(mode, 6).modes.refused().is_empty());
        }
    }

    #[test]
    fn atomic_write_on_a_file_is_refused_because_its_members_need_a_directory() {
        // The mode a caller is most likely to name on a single file, and the
        // one where a silently emptied rule would be least visible: three of
        // its four members are directory-only rights.
        let compiled = compile_one_file(FsMode::AtomicWrite, 6);
        let refused: Vec<FsMode> = compiled
            .modes
            .refused()
            .iter()
            .map(|refusal| refusal.mode)
            .collect();
        assert_eq!(
            refused,
            vec![FsMode::Create, FsMode::RemoveFile, FsMode::Rename],
            "every directory-only member must be named, not just the first"
        );
        for refusal in compiled.modes.refused() {
            assert!(matches!(
                refusal.why,
                RefusalReason::DirectoryOnlyRightOnFile { .. }
            ));
        }
        assert!(compiled.rights.is_empty());
    }

    #[test]
    fn a_kernel_that_lacks_the_right_says_so_before_the_path_type_does() {
        // Both gates fire on `rename` at ABI V1 on a file. The ABI answer is
        // the one that comes back, because a kernel without REFER cannot
        // restrict renaming at any path type — telling the caller to point at a
        // directory instead would be advice that does not work.
        let compiled = compile_one_file(FsMode::Rename, 1);
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
    }

    #[test]
    fn the_directory_only_split_is_the_kernels_access_file_set() {
        // ACCESS_FILE, spelled out: security/landlock/fs.c admits exactly
        // EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV in a rule on
        // a non-directory. IOCTL_DEV has no mode in this vocabulary, so four of
        // the five appear here. Restating the set is the point: a right that
        // silently changed sides would otherwise only show up as an EINVAL on a
        // kernel nobody ran the tests on.
        for right in [
            LandlockRightName::ReadFile,
            LandlockRightName::WriteFile,
            LandlockRightName::Execute,
            LandlockRightName::Truncate,
        ] {
            assert!(!right.is_directory_only(), "{right} is in ACCESS_FILE");
        }
        for right in [
            LandlockRightName::ReadDir,
            LandlockRightName::MakeReg,
            LandlockRightName::RemoveFile,
            LandlockRightName::RemoveDir,
            LandlockRightName::Refer,
        ] {
            assert!(right.is_directory_only(), "{right} is not in ACCESS_FILE");
        }
    }

    #[test]
    fn the_full_vocabulary_on_v6_refuses_nothing_and_invents_nothing() {
        let all = FsModeSet::of(&FsMode::ALL);
        let compiled = compile(all, V6, false);
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
