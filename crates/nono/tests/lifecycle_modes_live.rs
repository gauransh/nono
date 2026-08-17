//! Live mode-vocabulary tests: real Seatbelt profiles, real forks, real denials.
//!
//! Every test here drives the whole lifecycle — prepare, activate, wait — with a
//! capability set built from [`FsModeSet`] rather than the coarse
//! [`AccessMode`][nono::AccessMode] bundles, and checks the *kernel's* answer
//! rather than the profile text. A profile-string assertion proves that a
//! particular sentence was written; only a run proves it was enforced.
//!
//! # The shape of every test
//!
//! A positive/negative pair per mode. The two runs differ in exactly one mode,
//! so a pass says "this mode is what allowed it" and not "something in the grant
//! allowed it". The negative half is what makes each pair a
//! removal-detection test: weaken the profile — drop the `execute` scoping, emit
//! `file-read*` where the mode says `file-read-metadata` — and the negative
//! assertion fails.
//!
//! # Platform
//!
//! macOS only. The Linux mapping is unit-tested against a faked ABI in
//! `capability_modes::landlock_map` (which runs on every host) and its live half
//! is behind the R07 Linux-runner blocker; this file would report on a platform
//! it has not run on if it compiled there.
#![cfg(target_os = "macos")]

use nono::lifecycle::{
    ActivationError, ExitOutcome, PreExecStage, PreparedSandbox, SandboxExit, SandboxPlan,
    ValidatedPlan,
};
use nono::{CapabilitySet, FsMode, FsModeSet, Sandbox};
use std::path::Path;
use tempfile::TempDir;

/// What a helper binary needs to be found, mapped and run.
///
/// Read plus execute, and nothing else: no write anywhere under these paths, so
/// a test that accidentally wrote outside its own directory would fail rather
/// than pass quietly.
fn system_modes() -> FsModeSet {
    FsModeSet::of(&[
        FsMode::ReadContents,
        FsMode::ReadDir,
        FsMode::ReadMetadata,
        FsMode::Execute,
    ])
}

/// The system paths the helpers in this file load from.
///
/// Deliberately enumerated rather than granting `/`: the point of every test
/// below is that the *test's own directory* has a named set of modes, and a
/// recursive grant on `/` would cover it.
const SYSTEM_PATHS: [&str; 4] = ["/bin", "/usr", "/System", "/private/var/db"];

fn temp_dir() -> TempDir {
    match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(err) => panic!("test needs a temporary directory: {err}"),
    }
}

/// A capability set that can run a system binary and grants `modes` on `subject`.
fn caps_with(subject: &Path, modes: FsModeSet) -> CapabilitySet {
    let mut caps = CapabilitySet::new();
    for path in SYSTEM_PATHS {
        caps = match caps.allow_path_modes(path, system_modes()) {
            Ok(caps) => caps,
            Err(err) => panic!("system path {path} must be grantable: {err}"),
        };
    }
    match caps.allow_path_modes(subject, modes) {
        Ok(caps) => caps,
        Err(err) => panic!("subject {} must be grantable: {err}", subject.display()),
    }
}

fn plan_with(subject: &Path, modes: FsModeSet, program: &str, args: &[&str]) -> ValidatedPlan {
    let plan = SandboxPlan::new(program)
        .args(args.iter().copied())
        .capabilities(caps_with(subject, modes));
    match plan.validate() {
        Ok(plan) => plan,
        Err(err) => panic!("test plan must validate: {err}"),
    }
}

/// Run a plan to completion and return everything observed about the end.
fn run_exit(plan: ValidatedPlan) -> SandboxExit {
    let (mut held, handle) = match PreparedSandbox::prepare(plan) {
        Ok(pair) => pair,
        Err(err) => panic!("prepare must succeed: {err}"),
    };
    let mut running = match held.activate(&handle) {
        Ok(running) => running,
        Err(err) => panic!("activation must succeed: {err}"),
    };
    match running.wait() {
        Ok(exit) => exit,
        Err(err) => panic!("wait must observe the exit: {err}"),
    }
}

/// Run a plan to completion and return how it ended.
fn run(plan: ValidatedPlan) -> ExitOutcome {
    run_exit(plan).outcome()
}

/// Run `program` against `subject` granted `modes`, and return the outcome.
fn run_with(subject: &Path, modes: FsModeSet, program: &str, args: &[&str]) -> ExitOutcome {
    run(plan_with(subject, modes, program, args))
}

/// Activate a plan whose child is expected to die before `execve` completes.
///
/// A child that never reaches `execve` reports the fact on its status
/// descriptor, and the *gate* is where that is read — so the refusal arrives as
/// an [`ActivationError`], not as an exit status. Keeping the two apart is the
/// point: an exit status of 1 is something a customer program produces all the
/// time, and a denial that arrived as one would be indistinguishable from it.
fn activation_refusal(plan: ValidatedPlan) -> ActivationError {
    let (mut held, handle) = match PreparedSandbox::prepare(plan) {
        Ok(pair) => pair,
        Err(err) => panic!("prepare must succeed: {err}"),
    };
    match held.activate(&handle) {
        Ok(mut running) => {
            let outcome = running.wait().map(|exit| exit.outcome());
            panic!("activation was expected to fail; the run ended {outcome:?}");
        }
        Err(err) => err,
    }
}

/// Whether the run reached the program and the program said "fine".
fn succeeded(outcome: ExitOutcome) -> bool {
    outcome == ExitOutcome::Exited { code: 0 }
}

/// Assert that a run succeeded, and say everything known about it when it did
/// not.
///
/// A bare label is the least useful thing a live test can print. The first CI
/// run of this file on a newer macOS than the host that wrote it failed with
/// nothing but the sentence naming the expectation — which does not say whether
/// the program was denied by the profile, refused before `execve`, or killed,
/// nor what the profile was asked to contain. All three are here now:
///
/// - the [`SandboxExit`], which carries the outcome *and* whether the customer
///   program was ever observed to start (a `SandboxApplicationFailure` and an
///   `Exited { code: 1 }` are entirely different diagnoses);
/// - the modes as written, and what this platform compiled them into, so a
///   bundle or a refusal that changed under a new OS is visible in the failure
///   rather than in a second push.
///
/// Diagnostics only: the assertion is exactly the one it replaced.
fn assert_ran(subject: &Path, modes: FsModeSet, program: &str, args: &[&str], why: &str) {
    let exit = run_exit(plan_with(subject, modes, program, args));
    assert!(
        succeeded(exit.outcome()),
        "{why}\n  program:  {program} {args:?}\n  exit:     {exit:?}\n  \
         modes:    {modes}\n  compiled: {}",
        compiled_disclosure(subject, modes)
    );
}

/// What this platform says it will do with `modes` on `subject`.
///
/// The same compilation the profile is built from, so a failure prints the
/// disclosure rather than a guess about it.
fn compiled_disclosure(subject: &Path, modes: FsModeSet) -> String {
    match Sandbox::compile_fs_modes(&caps_with(subject, modes)) {
        Ok(compiled) => format!("{:?}", compiled.last()),
        Err(err) => format!("(compilation refused: {err})"),
    }
}

fn write_file(path: &Path, contents: &str) {
    if let Err(err) = std::fs::write(path, contents) {
        panic!("test fixture must be writable {}: {err}", path.display());
    }
}

fn string_of(path: &Path) -> String {
    match path.to_str() {
        Some(text) => text.to_string(),
        None => panic!("test paths are UTF-8 by construction"),
    }
}

// ---------------------------------------------------------------------------
// 0. The vocabulary reaches the kernel at all.
// ---------------------------------------------------------------------------

/// The baseline every other test rests on: a capability set built *only* from
/// mode grants can run a program. If this fails, every denial below would be a
/// denial of something unrelated.
#[test]
fn a_capability_set_built_from_modes_alone_can_run_a_program() {
    let dir = temp_dir();
    assert!(
        succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::ReadMetadata]),
            "/bin/echo",
            &["mode-vocabulary"],
        )),
        "a mode-built profile must be able to run /bin/echo"
    );
}

// ---------------------------------------------------------------------------
// 1. ReadContents — the pair that proves reading is a grant.
// ---------------------------------------------------------------------------

#[test]
fn read_contents_granted_reads_and_ungranted_is_denied() {
    let dir = temp_dir();
    let file = dir.path().join("subject");
    write_file(&file, "contents\n");
    let arg = string_of(&file);

    assert_ran(
        dir.path(),
        FsModeSet::of(&[FsMode::ReadContents, FsMode::ReadMetadata]),
        "/bin/cat",
        &[&arg],
        "read_contents must let cat read the file",
    );
    assert!(
        !succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::ReadMetadata]),
            "/bin/cat",
            &[&arg],
        )),
        "without read_contents, cat must be denied"
    );
}

// ---------------------------------------------------------------------------
// 2. ReadMetadata — the macOS-only distinction, proven.
// ---------------------------------------------------------------------------

/// The mode that exists because the two platforms differ.
///
/// One grant, `read_metadata` and nothing else, and two runs against it: `stat`
/// answers and `cat` is denied. On Linux this test could not exist — Landlock
/// has no right covering `stat(2)`, which is why the mode compiles to a
/// disclosed no-op there and why the support report calls it `unrestrictable`.
#[test]
fn read_metadata_alone_permits_stat_and_still_denies_reading_the_bytes() {
    let dir = temp_dir();
    let file = dir.path().join("subject");
    write_file(&file, "secret\n");
    let arg = string_of(&file);
    let metadata_only = FsModeSet::of(&[FsMode::ReadMetadata]);

    assert!(
        succeeded(run_with(
            dir.path(),
            metadata_only,
            "/usr/bin/stat",
            &["-f", "%z", &arg],
        )),
        "read_metadata must let stat(1) read the size"
    );
    assert!(
        !succeeded(run_with(dir.path(), metadata_only, "/bin/cat", &[&arg])),
        "read_metadata must NOT confer a data read: this is the whole distinction"
    );
}

// ---------------------------------------------------------------------------
// 3. ReadDir.
// ---------------------------------------------------------------------------

#[test]
fn read_dir_granted_lists_and_ungranted_is_denied() {
    let dir = temp_dir();
    write_file(&dir.path().join("entry"), "x\n");
    let arg = string_of(dir.path());

    assert!(
        succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::ReadDir, FsMode::ReadMetadata]),
            "/bin/ls",
            &[&arg],
        )),
        "read_dir must let ls list the directory"
    );
    assert!(
        !succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::ReadMetadata]),
            "/bin/ls",
            &[&arg],
        )),
        "without read_dir, ls must be denied"
    );
}

// ---------------------------------------------------------------------------
// 4. Write — isolated from Create by holding Create constant.
// ---------------------------------------------------------------------------

#[test]
fn write_granted_writes_and_ungranted_is_denied() {
    let dir = temp_dir();
    let file = dir.path().join("target");
    write_file(&file, "original\n");
    let script = format!("printf replaced > {}", shell_quote(&file));

    // The two runs differ in `write` alone: both hold `create`, so a failure
    // cannot be blamed on the open(2) creating flag.
    assert!(
        succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::Create, FsMode::Write, FsMode::ReadMetadata]),
            "/bin/sh",
            &["-c", &script],
        )),
        "write must let the shell write the file"
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap_or_default(),
        "replaced",
        "the granted run must really have changed the bytes"
    );

    write_file(&file, "original\n");
    assert!(
        !succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::Create, FsMode::ReadMetadata]),
            "/bin/sh",
            &["-c", &script],
        )),
        "without write, the shell must be denied"
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap_or_default(),
        "original\n",
        "the denied run must not have changed the bytes"
    );
}

// ---------------------------------------------------------------------------
// 5. Append, and the bundling disclosure that goes with it.
// ---------------------------------------------------------------------------

/// Append works, and the compile result *says* it is a write grant.
///
/// Seatbelt has no append-only operation, so an `append` grant compiles to
/// `file-write-data` — the same operation `write` compiles to. That is a real
/// widening, and the assertion on [`Sandbox::compile_fs_modes`] is the
/// disclosure: remove the bundle entry and this test fails, which is the point.
#[test]
fn append_works_and_is_disclosed_as_the_write_grant_it_really_is() {
    let dir = temp_dir();
    let file = dir.path().join("log");
    write_file(&file, "first\n");
    let script = format!("printf second >> {}", shell_quote(&file));
    let append_only = FsModeSet::of(&[FsMode::Append, FsMode::ReadMetadata]);

    let caps = caps_with(dir.path(), append_only);
    let compiled = match Sandbox::compile_fs_modes(&caps) {
        Ok(compiled) => compiled,
        Err(err) => panic!("the mode set must compile on this platform: {err}"),
    };
    let Some(subject) = compiled.last() else {
        panic!("the subject grant is the last one added");
    };
    let Some(bundle) = subject.bundle_for(FsMode::Write) else {
        panic!(
            "an append grant confers write on this platform and must disclose it; \
             compiled = {subject:?}"
        );
    };
    assert_eq!(bundle.requested, FsMode::Append);
    assert_eq!(bundle.also_granted, FsMode::Write);
    assert_eq!(
        bundle.why,
        nono::BundleReason::AppendImpliesWrite,
        "the disclosure must name the reason, not just the fact"
    );

    assert!(
        succeeded(run_with(
            dir.path(),
            append_only,
            "/bin/sh",
            &["-c", &script],
        )),
        "append must let the shell append to the file"
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap_or_default(),
        "first\nsecond"
    );

    write_file(&file, "first\n");
    assert!(
        !succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::ReadMetadata]),
            "/bin/sh",
            &["-c", &script],
        )),
        "without append, the shell must be denied"
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap_or_default(),
        "first\n"
    );
}

// ---------------------------------------------------------------------------
// 6. Create.
// ---------------------------------------------------------------------------

#[test]
fn create_granted_makes_a_new_file_and_ungranted_is_denied() {
    let dir = temp_dir();
    let made = dir.path().join("made");
    let arg = string_of(&made);

    assert!(
        succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::Create, FsMode::Write, FsMode::ReadMetadata]),
            "/usr/bin/touch",
            &[&arg],
        )),
        "create must let touch make a new file"
    );
    assert!(made.exists(), "the granted run must really have created it");

    if let Err(err) = std::fs::remove_file(&made) {
        panic!("the fixture must be removable: {err}");
    }
    assert!(
        !succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::Write, FsMode::ReadMetadata]),
            "/usr/bin/touch",
            &[&arg],
        )),
        "without create, touch must be denied"
    );
    assert!(
        !made.exists(),
        "the denied run must not have created anything"
    );
}

// ---------------------------------------------------------------------------
// 7. RemoveFile.
// ---------------------------------------------------------------------------

#[test]
fn remove_file_granted_unlinks_and_ungranted_is_denied() {
    let dir = temp_dir();
    let victim = dir.path().join("victim");
    write_file(&victim, "x\n");
    let arg = string_of(&victim);

    assert!(
        !succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::ReadMetadata]),
            "/bin/rm",
            &[&arg],
        )),
        "without remove_file, rm must be denied"
    );
    assert!(victim.exists(), "the denied run must not have unlinked it");

    assert!(
        succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::RemoveFile, FsMode::ReadMetadata]),
            "/bin/rm",
            &[&arg],
        )),
        "remove_file must let rm unlink the file"
    );
    assert!(
        !victim.exists(),
        "the granted run must really have unlinked it"
    );
}

// ---------------------------------------------------------------------------
// 8. RemoveDir.
// ---------------------------------------------------------------------------

#[test]
fn remove_dir_granted_rmdirs_and_ungranted_is_denied() {
    let dir = temp_dir();
    let victim = dir.path().join("victim-dir");
    if let Err(err) = std::fs::create_dir(&victim) {
        panic!("the fixture directory must be creatable: {err}");
    }
    let arg = string_of(&victim);

    assert!(
        !succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::ReadMetadata]),
            "/bin/rmdir",
            &[&arg],
        )),
        "without remove_dir, rmdir must be denied"
    );
    assert!(victim.exists(), "the denied run must not have removed it");

    assert!(
        succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::RemoveDir, FsMode::ReadMetadata]),
            "/bin/rmdir",
            &[&arg],
        )),
        "remove_dir must let rmdir remove the directory"
    );
    assert!(
        !victim.exists(),
        "the granted run must really have removed it"
    );
}

// ---------------------------------------------------------------------------
// 9. Rename.
// ---------------------------------------------------------------------------

#[test]
fn rename_granted_moves_within_the_directory_and_ungranted_is_denied() {
    let dir = temp_dir();
    let from = dir.path().join("before");
    let to = dir.path().join("after");
    write_file(&from, "x\n");
    let from_arg = string_of(&from);
    let to_arg = string_of(&to);

    assert!(
        !succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::ReadMetadata]),
            "/bin/mv",
            &[&from_arg, &to_arg],
        )),
        "without rename, mv must be denied"
    );
    assert!(
        from.exists() && !to.exists(),
        "the denied run must not have moved it"
    );

    assert!(
        succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::Rename, FsMode::ReadMetadata]),
            "/bin/mv",
            &[&from_arg, &to_arg],
        )),
        "rename must let mv move the file within the directory"
    );
    assert!(
        !from.exists() && to.exists(),
        "the granted run must really have moved it"
    );
}

// ---------------------------------------------------------------------------
// 10. Execute — the mode that turns `(allow process-exec*)` into a capability.
// ---------------------------------------------------------------------------

/// A program the sandbox has never heard of, run twice.
///
/// This is the mode that changes upstream behaviour: without it, macOS profiles
/// carry an unconditional `(allow process-exec*)` and which program a confined
/// process runs is not a capability at all. The negative half is the proof —
/// the program is readable and mappable in both runs, and only `execute`
/// decides whether it runs.
///
/// The refusal is observed as a typed
/// [`ActivationError::PreExecFailed`] at [`PreExecStage::Exec`] with `EPERM`:
/// no shell wraps the program, so nothing can turn a denial into an exit status
/// that merely resembles one.
///
/// # Why the fixture is a script and not a copied binary
///
/// A byte-for-byte copy of a platform binary cannot be `execve`d on this host
/// **at all**, sandbox or no sandbox: the kernel `SIGKILL`s it because its code
/// signature is not the one the trust cache has for that path, and re-signing it
/// ad-hoc (`codesign --sign -`) does not change that. Verified outside any
/// sandbox before choosing the fixture. A `#!` script is unsigned by nature, so
/// the only thing standing between it and running is the grant — which is what
/// the test is about. It also exercises the `*` in `process-exec*`: the kernel
/// execs the interpreter, and that is a `process-exec-interpreter` check
/// against `/bin/sh`, which the system grant covers.
#[test]
fn execute_granted_runs_an_unheard_of_program_and_ungranted_is_refused_at_exec() {
    let dir = temp_dir();
    let script = dir.path().join("helper");
    write_file(&script, "#!/bin/sh\nexit 0\n");
    if let Err(err) = std::fs::set_permissions(
        &script,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
    ) {
        panic!("the fixture must be made executable: {err}");
    }
    let program = string_of(&script);

    let denied = activation_refusal(
        match SandboxPlan::new(&program)
            .args(["ran"])
            .capabilities(caps_with(
                dir.path(),
                FsModeSet::of(&[FsMode::ReadContents, FsMode::ReadMetadata]),
            ))
            .validate()
        {
            Ok(plan) => plan,
            Err(err) => panic!("test plan must validate: {err}"),
        },
    );
    assert_eq!(
        denied,
        ActivationError::PreExecFailed {
            stage: PreExecStage::Exec,
            errno: libc::EPERM,
        },
        "a readable but not executable path must be refused at execve with EPERM"
    );

    let allowed = run(
        match SandboxPlan::new(&program)
            .args(["ran"])
            .capabilities(caps_with(
                dir.path(),
                FsModeSet::of(&[FsMode::ReadContents, FsMode::ReadMetadata, FsMode::Execute]),
            ))
            .validate()
        {
            Ok(plan) => plan,
            Err(err) => panic!("test plan must validate: {err}"),
        },
    );
    assert!(
        succeeded(allowed),
        "execute must let the program run, got {allowed:?}"
    );
}

// ---------------------------------------------------------------------------
// 11. Truncate — bundled with Write here, and behaving as disclosed.
// ---------------------------------------------------------------------------

/// Truncation is `file-write-data` on this platform, so the pair is a write
/// pair — and the compile result says so rather than leaving it to be inferred.
#[test]
fn truncate_behaves_as_the_write_bundle_the_compile_result_discloses() {
    let dir = temp_dir();
    let file = dir.path().join("fat");
    write_file(&file, "aaaaaaaaaaaaaaaa\n");
    let script = format!(": > {}", shell_quote(&file));
    let truncating = FsModeSet::of(&[FsMode::Truncate, FsMode::ReadMetadata]);

    let caps = caps_with(dir.path(), truncating);
    let compiled = match Sandbox::compile_fs_modes(&caps) {
        Ok(compiled) => compiled,
        Err(err) => panic!("the mode set must compile on this platform: {err}"),
    };
    let Some(subject) = compiled.last() else {
        panic!("the subject grant is the last one added");
    };
    let Some(bundle) = subject.bundle_for(FsMode::Write) else {
        panic!("a truncate grant confers write here and must disclose it: {subject:?}");
    };
    assert_eq!(bundle.why, nono::BundleReason::SeatbeltTruncateIsWriteData);

    assert!(
        succeeded(run_with(
            dir.path(),
            truncating,
            "/bin/sh",
            &["-c", &script],
        )),
        "truncate must let the shell shorten the file"
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap_or_default(),
        "",
        "the granted run must really have truncated it"
    );

    write_file(&file, "aaaaaaaaaaaaaaaa\n");
    assert!(
        !succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::ReadMetadata]),
            "/bin/sh",
            &["-c", &script],
        )),
        "without the write bundle, truncation must be denied"
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap_or_default(),
        "aaaaaaaaaaaaaaaa\n"
    );
}

// ---------------------------------------------------------------------------
// 12. AtomicWrite — the whole cluster, as one word.
// ---------------------------------------------------------------------------

/// `printf > tmp && mv tmp real`: the pattern real tools use, granted by name.
///
/// The negative half holds `write` — so the temp file's *contents* are not the
/// obstacle — and withholds the create/rename half, which is exactly what
/// `atomic_write` adds.
#[test]
fn atomic_write_grants_the_temp_file_dance_and_write_alone_does_not() {
    let dir = temp_dir();
    let target = dir.path().join("config");
    let temp = dir.path().join("config.new");
    write_file(&target, "old\n");
    let script = format!(
        "printf new > {} && mv {} {}",
        shell_quote(&temp),
        shell_quote(&temp),
        shell_quote(&target)
    );

    assert!(
        !succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::Write, FsMode::ReadMetadata]),
            "/bin/sh",
            &["-c", &script],
        )),
        "write alone must not be enough for the temp-file dance"
    );
    assert_eq!(
        std::fs::read_to_string(&target).unwrap_or_default(),
        "old\n",
        "the denied run must not have replaced the target"
    );

    assert!(
        succeeded(run_with(
            dir.path(),
            FsModeSet::of(&[FsMode::AtomicWrite, FsMode::ReadMetadata]),
            "/bin/sh",
            &["-c", &script],
        )),
        "atomic_write must grant create + write + rename + remove_file"
    );
    assert_eq!(
        std::fs::read_to_string(&target).unwrap_or_default(),
        "new",
        "the granted run must really have replaced the target"
    );
}

/// The members `atomic_write` stands for are disclosed, not implied.
#[test]
fn atomic_write_discloses_every_member_it_stands_for() {
    let dir = temp_dir();
    let caps = caps_with(dir.path(), FsModeSet::empty().with(FsMode::AtomicWrite));
    let compiled = match Sandbox::compile_fs_modes(&caps) {
        Ok(compiled) => compiled,
        Err(err) => panic!("the mode set must compile on this platform: {err}"),
    };
    let Some(subject) = compiled.last() else {
        panic!("the subject grant is the last one added");
    };
    for member in FsMode::ATOMIC_WRITE_MEMBERS {
        let Some(bundle) = subject.bundle_for(member) else {
            panic!("atomic_write must disclose that it grants {member}: {subject:?}");
        };
        assert_eq!(bundle.requested, FsMode::AtomicWrite);
        assert_eq!(bundle.why, nono::BundleReason::AtomicWriteCluster);
    }
}

/// Quote a path for `/bin/sh -c`.
///
/// Single quotes with the `'\''` escape: the only character a single-quoted
/// shell word cannot contain is a single quote, and this is how it is spelled.
fn shell_quote(path: &Path) -> String {
    let text = string_of(path);
    format!("'{}'", text.replace('\'', "'\\''"))
}

// ===========================================================================
// diag(modes): TEMPORARY DIAGNOSTIC — DELETE WITH THE FIX.
//
// Why: `read_contents_granted_reads_and_ungranted_is_denied` fails only on the
// GitHub macos-latest runner (Darwin 26, macOS 26) and passes on Darwin 23.
// The runner's gate log already shows the child printing
// `cat: stdout: Operation not permitted` — an error about the *inherited
// stdout*, not about the subject file. This test settles which call it is and
// whether the subject read itself works, from the failing host.
//
// It ends in a panic on purpose: libtest only prints a test's captured output
// when the test fails.
// ===========================================================================

/// Run a program *outside* any sandbox and report everything it said.
fn diag_host_command(program: &str, args: &[&str]) -> String {
    match std::process::Command::new(program).args(args).output() {
        Ok(out) => format!(
            "status={:?} stdout={:?} stderr={:?}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(err) => format!("(spawn failed: {err})"),
    }
}

/// What a standard stream really is: its path (if it has one) and its vnode.
fn diag_fd(fd: std::os::unix::io::RawFd) -> String {
    let mut buf = [0_u8; 1024];
    // SAFETY: temporary diagnostic. `buf` is a live PATH_MAX-sized buffer,
    // which is what F_GETPATH writes into, and `fd` is a standard stream.
    let got = unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr().cast::<libc::c_char>()) };
    let path = if got == 0 {
        let end = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).to_string()
    } else {
        format!("(F_GETPATH failed: {})", std::io::Error::last_os_error())
    };
    // SAFETY: temporary diagnostic. `stat` is a live, zeroed `libc::stat` and
    // `fd` is a standard stream.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let rc = unsafe { libc::fstat(fd, &raw mut stat) };
    let kind = if rc == 0 {
        format!(
            "st_mode=0o{:o} st_blksize={}",
            stat.st_mode, stat.st_blksize
        )
    } else {
        format!("(fstat failed: {})", std::io::Error::last_os_error())
    };
    format!("fd {fd}: path={path} {kind}")
}

/// The path behind a descriptor, when it has one.
fn diag_fd_path(fd: std::os::unix::io::RawFd) -> Option<std::path::PathBuf> {
    let mut buf = [0_u8; 1024];
    // SAFETY: as in `diag_fd`.
    let got = unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr().cast::<libc::c_char>()) };
    if got != 0 {
        return None;
    }
    let end = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
    let text = String::from_utf8_lossy(&buf[..end]).to_string();
    let path = std::path::PathBuf::from(text);
    if path.is_file() { Some(path) } else { None }
}

/// Run one sandboxed probe and print its outcome under `label`.
fn diag_run(label: &str, caps: CapabilitySet, program: &str, args: &[&str]) {
    let plan = SandboxPlan::new(program)
        .args(args.iter().copied())
        .capabilities(caps);
    let outcome = match plan.validate() {
        Ok(plan) => format!("{:?}", run_exit(plan).outcome()),
        Err(err) => format!("(validate refused: {err})"),
    };
    println!("diag[{label}]: {program} {args:?} -> {outcome}");
}

#[test]
fn diag_read_contents_on_this_host() {
    println!(
        "diag: sw_vers  {}",
        diag_host_command("/usr/bin/sw_vers", &[])
    );
    println!(
        "diag: uname -a {}",
        diag_host_command("/usr/bin/uname", &["-a"])
    );
    for fd in [0, 1, 2] {
        println!("diag: {}", diag_fd(fd));
    }

    let dir = temp_dir();
    let file = dir.path().join("subject");
    write_file(&file, "contents\n");
    let arg = string_of(&file);
    let canonical = match std::fs::canonicalize(&file) {
        Ok(path) => string_of(&path),
        Err(err) => format!("(canonicalize failed: {err})"),
    };
    println!("diag: subject literal   {arg}");
    println!("diag: subject canonical {canonical}");

    let read = FsModeSet::of(&[FsMode::ReadContents, FsMode::ReadMetadata]);

    // 1. The failing probe, reproduced.
    diag_run(
        "cat-baseline",
        caps_with(dir.path(), read),
        "/bin/cat",
        &[&arg],
    );

    // 2. The canonical spelling of the same file, in case the literal /var
    //    spelling is what the newer kernel objects to.
    diag_run(
        "cat-canonical-arg",
        caps_with(dir.path(), read),
        "/bin/cat",
        &[&canonical],
    );

    // 3. Readers that do not touch stdout the way cat(1) does. `cmp -s` reads
    //    both files' bytes and prints nothing at all; `wc -l` must read every
    //    byte to count lines.
    diag_run(
        "cmp-silent",
        caps_with(dir.path(), read),
        "/usr/bin/cmp",
        &["-s", &arg, &arg],
    );
    diag_run(
        "wc-lines",
        caps_with(dir.path(), read),
        "/usr/bin/wc",
        &["-l", &arg],
    );

    // 4. cat again, with the *inherited stdout's own path* granted, one mode at
    //    a time. Whichever of these turns the exit into 0 names the operation
    //    macOS 26 is checking that Darwin 23 is not.
    match diag_fd_path(1) {
        Some(stdout_path) => {
            println!("diag: stdout path = {}", stdout_path.display());
            for (label, modes) in [
                ("stdout-metadata", FsModeSet::of(&[FsMode::ReadMetadata])),
                ("stdout-write", FsModeSet::of(&[FsMode::Write])),
                (
                    "stdout-read-write",
                    FsModeSet::of(&[FsMode::ReadContents, FsMode::ReadMetadata, FsMode::Write]),
                ),
            ] {
                let caps = match caps_with(dir.path(), read).allow_file_modes(&stdout_path, modes) {
                    Ok(caps) => caps,
                    Err(err) => {
                        println!("diag[cat+{label}]: (grant refused: {err})");
                        continue;
                    }
                };
                diag_run(&format!("cat+{label}"), caps, "/bin/cat", &[&arg]);
            }
        }
        None => println!("diag: stdout has no path (pipe or tty); skipped the stdout grants"),
    }

    // 5. The same read from a subject that is not under /var/folders, in case
    //    the per-user temp confinement is what differs.
    let repo_temp = Path::new(env!("CARGO_MANIFEST_DIR")).join("diag-modes-tmp");
    if let Err(err) = std::fs::create_dir_all(&repo_temp) {
        println!("diag: repo-local subject unavailable: {err}");
    } else {
        let repo_file = repo_temp.join("subject");
        write_file(&repo_file, "contents\n");
        let repo_arg = string_of(&repo_file);
        diag_run(
            "cat-repo-local",
            caps_with(&repo_temp, read),
            "/bin/cat",
            &[&repo_arg],
        );
        let _ = std::fs::remove_dir_all(&repo_temp);
    }

    // 6. What the kernel itself logged. The predicate is the one nono-cli's
    //    sandbox_log.rs uses.
    match std::process::Command::new("/usr/bin/log")
        .args([
            "show",
            "--last",
            "2m",
            "--style",
            "compact",
            "--predicate",
            "((processID == 0) AND (senderImagePath CONTAINS \"/Sandbox\")) OR \
             (process == \"sandboxd\") OR (subsystem == \"com.apple.sandbox.reporting\")",
        ])
        .output()
    {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            let interesting: Vec<&str> = text
                .lines()
                .filter(|line| line.contains("deny") || line.contains("Sandbox"))
                .collect();
            println!(
                "diag: log show status={:?} lines={} matched={} stderr={:?}",
                out.status.code(),
                text.lines().count(),
                interesting.len(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
            for line in interesting.iter().rev().take(40) {
                println!("diag: log {line}");
            }
        }
        Err(err) => println!("diag: log show unavailable: {err}"),
    }

    panic!("diag(modes): temporary diagnostic — read the captured output above");
}
