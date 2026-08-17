//! [`FsMode`] to Seatbelt SBPL operations.
//!
//! Compiled on every platform for the same reason [`super::landlock_map`] is:
//! the mapping is a table, and a table should be testable on whichever machine
//! is running the tests. Nothing here calls `sandbox_init`; the emitter that
//! turns these operations into profile text lives in `crate::sandbox::macos`.
//!
//! Seatbelt's filesystem vocabulary is coarser than Landlock's in most places
//! and finer in exactly one: it has `file-read-metadata`, so macOS can enforce
//! [`FsMode::ReadMetadata`] and Linux cannot. Every place it is coarser produces
//! a [`BundleReason`] rather than a silent superset.

use super::{
    BundleReason, CompiledModes, FsMode, FsModeSet, ModeTarget, RefusalReason, compile_common,
};

/// A Seatbelt operation, spelled as it appears in a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SbplOperation {
    /// `file-read-data` — `read(2)` on a file, `readdir(3)` on a directory.
    FileReadData,
    /// `file-read-metadata` — `stat(2)` and friends. The one operation macOS
    /// can restrict and Linux cannot.
    FileReadMetadata,
    /// `file-write-data` — writing, appending and truncating alike.
    FileWriteData,
    /// `file-write-create` — creating a node of any type.
    FileWriteCreate,
    /// `file-write-unlink` — `unlink(2)` and `rmdir(2)` alike.
    FileWriteUnlink,
    /// `process-exec*` — `execve(2)`, scoped to a path filter. Covers
    /// `process-exec-interpreter` so a `#!` script whose interpreter is granted
    /// still runs.
    ProcessExec,
    /// `file-map-executable` — mapping a file `PROT_EXEC`, which `dyld` needs
    /// for the binary itself and for every library it loads.
    FileMapExecutable,
}

impl SbplOperation {
    /// The operation name as written in a profile.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SbplOperation::FileReadData => "file-read-data",
            SbplOperation::FileReadMetadata => "file-read-metadata",
            SbplOperation::FileWriteData => "file-write-data",
            SbplOperation::FileWriteCreate => "file-write-create",
            SbplOperation::FileWriteUnlink => "file-write-unlink",
            SbplOperation::ProcessExec => "process-exec*",
            SbplOperation::FileMapExecutable => "file-map-executable",
        }
    }
}

impl std::fmt::Display for SbplOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What compiling an [`FsModeSet`] for Seatbelt produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledSbpl {
    /// What the platform will and will not do with each mode.
    pub modes: CompiledModes,
    /// Operations to allow on the granted path, sorted and deduplicated.
    pub operations: Vec<SbplOperation>,
    /// Operations to allow on the *hex-suffixed temp sibling* of a file grant
    /// (`<path>.tmp.<pid>.<hex>`), for [`FsMode::AtomicWrite`]. Empty unless
    /// atomic write was granted on a single file — a directory grant already
    /// covers the sibling through its subpath.
    pub temp_sibling_operations: Vec<SbplOperation>,
}

/// The operations one mode needs.
///
/// The whole Seatbelt half of the contract, in one table:
///
/// | mode | operations |
/// |---|---|
/// | `read_contents` | `file-read-data`, `file-map-executable` |
/// | `read_dir` | `file-read-data` |
/// | `read_metadata` | `file-read-metadata` |
/// | `write` | `file-write-data` |
/// | `append` | `file-write-data` |
/// | `create` | `file-write-create` |
/// | `truncate` | `file-write-data` |
/// | `remove_file` | `file-write-unlink` |
/// | `remove_dir` | `file-write-unlink` |
/// | `rename` | `file-write-create`, `file-write-unlink` |
/// | `execute` | `process-exec*`, `file-map-executable` |
/// | `unix_socket_connect` | *(none — delegated)* |
/// | `atomic_write` | *(none of its own — see its members)* |
///
/// `file-map-executable` rides with `read_contents` because that is where
/// upstream's `generate_profile` puts it (it is emitted for every readable
/// capability) and because `dyld` maps every library it loads out of paths the
/// process can read. It is **not** an exec grant: `process-exec*` is the gate,
/// and a path with `read_contents` but no `execute` still cannot be `execve`d.
#[must_use]
pub fn operations_for(mode: FsMode) -> &'static [SbplOperation] {
    match mode {
        FsMode::ReadContents => &[SbplOperation::FileReadData, SbplOperation::FileMapExecutable],
        FsMode::ReadDir => &[SbplOperation::FileReadData],
        FsMode::ReadMetadata => &[SbplOperation::FileReadMetadata],
        FsMode::Write | FsMode::Append | FsMode::Truncate => &[SbplOperation::FileWriteData],
        FsMode::Create => &[SbplOperation::FileWriteCreate],
        FsMode::RemoveFile | FsMode::RemoveDir => &[SbplOperation::FileWriteUnlink],
        FsMode::Rename => &[SbplOperation::FileWriteCreate, SbplOperation::FileWriteUnlink],
        FsMode::Execute => &[SbplOperation::ProcessExec, SbplOperation::FileMapExecutable],
        // Enforced by the UnixSocketCapability's own network-outbound rules.
        FsMode::UnixSocketConnect
        // A name for its members, which carry their own operations.
        | FsMode::AtomicWrite => &[],
    }
}

/// Modes Seatbelt cannot tell apart, and why.
///
/// Every entry is a place where two operations in the contract are one
/// operation in SBPL. They are symmetric because the underlying check is: if
/// `file-write-data` is allowed, both writing and truncating are allowed, and
/// there is no order in which that stops being true.
pub(super) fn implications(mode: FsMode, target: ModeTarget) -> &'static [(FsMode, BundleReason)] {
    debug_assert!(matches!(target, ModeTarget::Seatbelt));
    match mode {
        FsMode::Write => &[
            (FsMode::Append, BundleReason::AppendImpliesWrite),
            (FsMode::Truncate, BundleReason::SeatbeltTruncateIsWriteData),
        ],
        FsMode::Append => &[
            (FsMode::Write, BundleReason::AppendImpliesWrite),
            (FsMode::Truncate, BundleReason::SeatbeltTruncateIsWriteData),
        ],
        FsMode::Truncate => &[
            (FsMode::Write, BundleReason::SeatbeltTruncateIsWriteData),
            (FsMode::Append, BundleReason::SeatbeltTruncateIsWriteData),
        ],
        FsMode::RemoveFile => &[(
            FsMode::RemoveDir,
            BundleReason::SeatbeltUnlinkCoversFilesAndDirectories,
        )],
        FsMode::RemoveDir => &[(
            FsMode::RemoveFile,
            BundleReason::SeatbeltUnlinkCoversFilesAndDirectories,
        )],
        FsMode::ReadContents => &[(
            FsMode::ReadDir,
            BundleReason::SeatbeltReadDataCoversFilesAndDirectories,
        )],
        FsMode::ReadDir => &[(
            FsMode::ReadContents,
            BundleReason::SeatbeltReadDataCoversFilesAndDirectories,
        )],
        // Seatbelt has no rename operation at all: a rename is checked as a
        // create on the destination and an unlink on the source, so granting it
        // really does grant both.
        FsMode::Rename => &[
            (
                FsMode::Create,
                BundleReason::SeatbeltRenameIsCreatePlusUnlink,
            ),
            (
                FsMode::RemoveFile,
                BundleReason::SeatbeltRenameIsCreatePlusUnlink,
            ),
        ],
        FsMode::AtomicWrite => &[
            (FsMode::Create, BundleReason::AtomicWriteCluster),
            (FsMode::Write, BundleReason::AtomicWriteCluster),
            (FsMode::Rename, BundleReason::AtomicWriteCluster),
            (FsMode::RemoveFile, BundleReason::AtomicWriteCluster),
        ],
        _ => &[],
    }
}

/// Compile `requested` for Seatbelt.
///
/// `is_file` selects whether an [`FsMode::AtomicWrite`] grant needs the
/// temp-sibling rule: a directory grant is a `subpath`, so the temp file is
/// already inside it, while a file grant is a `literal` and the temp file is a
/// different path entirely.
///
/// Nothing is ever refused here. Seatbelt has no version gates, so the refusal
/// list is structurally empty on this platform — which is itself a fact worth
/// being able to read rather than assume.
#[must_use]
pub fn compile(requested: FsModeSet, is_file: bool) -> CompiledSbpl {
    let (modes, granted) = compile_common(
        requested,
        ModeTarget::Seatbelt,
        implications,
        // Seatbelt is not versioned and has no ABI gates: every operation this
        // table names has existed for as long as `sandbox_init` has.
        |_mode| Option::<RefusalReason>::None,
    );

    let mut operations: Vec<SbplOperation> = granted
        .iter()
        .flat_map(|mode| operations_for(mode).iter().copied())
        .collect();
    operations.sort_unstable();
    operations.dedup();

    // The hex-suffixed temp sibling. Ported from nono-cli's
    // `add_atomic_write_rule` (crates/nono-cli/src/capability_ext.rs:434-460,
    // hex-suffix + read-metadata fix in 5f0b95a0), which discovered the pattern
    // — `<target>.tmp.<pid>.<hex>` — that real tools write. Narrower than the
    // original on purpose: upstream emits `file-write*`, this emits only the
    // four operations a temp-file write actually performs.
    let temp_sibling_operations = if is_file && granted.contains(FsMode::AtomicWrite) {
        vec![
            SbplOperation::FileReadMetadata,
            SbplOperation::FileWriteData,
            SbplOperation::FileWriteCreate,
            SbplOperation::FileWriteUnlink,
        ]
    } else {
        Vec::new()
    };

    CompiledSbpl {
        modes,
        operations,
        temp_sibling_operations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_modes::DelegationTarget;

    fn compile_one(mode: FsMode) -> CompiledSbpl {
        compile(FsModeSet::empty().with(mode), false)
    }

    #[test]
    fn every_mode_maps_to_the_operations_the_contract_names() {
        let table = [
            (
                FsMode::ReadContents,
                vec![
                    SbplOperation::FileReadData,
                    SbplOperation::FileMapExecutable,
                ],
            ),
            (FsMode::ReadDir, vec![SbplOperation::FileReadData]),
            (FsMode::ReadMetadata, vec![SbplOperation::FileReadMetadata]),
            (FsMode::Write, vec![SbplOperation::FileWriteData]),
            (FsMode::Append, vec![SbplOperation::FileWriteData]),
            (FsMode::Truncate, vec![SbplOperation::FileWriteData]),
            (FsMode::Create, vec![SbplOperation::FileWriteCreate]),
            (FsMode::RemoveFile, vec![SbplOperation::FileWriteUnlink]),
            (FsMode::RemoveDir, vec![SbplOperation::FileWriteUnlink]),
            (
                FsMode::Rename,
                vec![
                    SbplOperation::FileWriteCreate,
                    SbplOperation::FileWriteUnlink,
                ],
            ),
            (
                FsMode::Execute,
                vec![SbplOperation::ProcessExec, SbplOperation::FileMapExecutable],
            ),
        ];
        for (mode, expected) in table {
            for operation in expected {
                assert!(
                    compile_one(mode).operations.contains(&operation),
                    "{mode} must compile to {operation}"
                );
            }
        }
    }

    #[test]
    fn read_metadata_is_enforceable_here_unlike_on_linux() {
        let compiled = compile_one(FsMode::ReadMetadata);
        assert_eq!(compiled.operations, vec![SbplOperation::FileReadMetadata]);
        assert_eq!(compiled.modes.enforced(), &[FsMode::ReadMetadata]);
        assert!(
            compiled.modes.always_allowed().is_empty(),
            "macOS restricts stat(2); reporting it as always-allowed would be wrong"
        );
        // The distinction that makes the mode worth having: a metadata grant
        // does not confer a data read.
        assert!(!compiled.operations.contains(&SbplOperation::FileReadData));
        assert!(!compiled.modes.grants(FsMode::ReadContents));
    }

    #[test]
    fn write_append_and_truncate_are_one_operation_and_it_is_disclosed() {
        let compiled = compile_one(FsMode::Write);
        assert_eq!(compiled.operations, vec![SbplOperation::FileWriteData]);
        let append = match compiled.modes.bundle_for(FsMode::Append) {
            Some(bundle) => bundle,
            None => panic!("a write grant must disclose that it also appends"),
        };
        assert_eq!(append.why, BundleReason::AppendImpliesWrite);
        let truncate = match compiled.modes.bundle_for(FsMode::Truncate) {
            Some(bundle) => bundle,
            None => panic!("a write grant must disclose that it also truncates"),
        };
        assert_eq!(truncate.why, BundleReason::SeatbeltTruncateIsWriteData);
    }

    #[test]
    fn rename_is_disclosed_as_the_create_plus_unlink_pair_it_really_is() {
        let compiled = compile_one(FsMode::Rename);
        assert_eq!(
            compiled.operations,
            vec![
                SbplOperation::FileWriteCreate,
                SbplOperation::FileWriteUnlink
            ]
        );
        for member in [FsMode::Create, FsMode::RemoveFile] {
            let bundle = match compiled.modes.bundle_for(member) {
                Some(bundle) => bundle,
                None => panic!("a rename grant must disclose that it also grants {member}"),
            };
            assert_eq!(bundle.why, BundleReason::SeatbeltRenameIsCreatePlusUnlink);
        }
        // And transitively: unlink cannot be narrowed to files.
        assert!(compiled.modes.grants(FsMode::RemoveDir));
    }

    #[test]
    fn unlink_cannot_be_narrowed_to_files_and_says_so() {
        let compiled = compile_one(FsMode::RemoveFile);
        let bundle = match compiled.modes.bundle_for(FsMode::RemoveDir) {
            Some(bundle) => bundle,
            None => panic!("a remove-file grant must disclose that it also removes directories"),
        };
        assert_eq!(
            bundle.why,
            BundleReason::SeatbeltUnlinkCoversFilesAndDirectories
        );
    }

    #[test]
    fn execute_is_a_path_scoped_process_exec_not_a_read() {
        let compiled = compile_one(FsMode::Execute);
        assert!(compiled.operations.contains(&SbplOperation::ProcessExec));
        assert!(!compiled.operations.contains(&SbplOperation::FileReadData));
        // And the converse, which is what makes the exec negative test mean
        // something: a readable path is not an executable one.
        assert!(
            !compile_one(FsMode::ReadContents)
                .operations
                .contains(&SbplOperation::ProcessExec)
        );
    }

    #[test]
    fn atomic_write_on_a_file_adds_the_hex_suffixed_temp_sibling_rule() {
        let file = compile(FsModeSet::empty().with(FsMode::AtomicWrite), true);
        assert_eq!(
            file.temp_sibling_operations,
            vec![
                SbplOperation::FileReadMetadata,
                SbplOperation::FileWriteData,
                SbplOperation::FileWriteCreate,
                SbplOperation::FileWriteUnlink,
            ]
        );
        // A directory grant is a subpath; the temp file is already inside it.
        let dir = compile(FsModeSet::empty().with(FsMode::AtomicWrite), false);
        assert!(dir.temp_sibling_operations.is_empty());
        assert!(dir.operations.contains(&SbplOperation::FileWriteCreate));
        assert!(dir.operations.contains(&SbplOperation::FileWriteUnlink));
        assert!(dir.operations.contains(&SbplOperation::FileWriteData));
    }

    #[test]
    fn seatbelt_refuses_nothing_because_it_has_no_version_gates() {
        let compiled = compile(FsModeSet::of(&FsMode::ALL), true);
        assert!(compiled.modes.refused().is_empty());
        assert_eq!(
            compiled.modes.delegated(),
            &[crate::capability_modes::ModeDelegation {
                mode: FsMode::UnixSocketConnect,
                target: DelegationTarget::UnixSocketCapability,
            }][..]
        );
    }
}
