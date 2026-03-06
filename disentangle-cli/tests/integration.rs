use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;

fn cli() -> Command {
    cargo_bin_cmd!("disentangle")
}

// =============================================================================
// Help and version
// =============================================================================

#[test]
fn help_flag_exits_zero() {
    cli()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("CLI for the Disentangle Protocol"));
}

#[test]
fn version_flag_exits_zero() {
    cli().arg("--version").assert().success();
}

// =============================================================================
// Unknown / missing subcommands
// =============================================================================

#[test]
fn unknown_subcommand_exits_nonzero() {
    cli().arg("foobar").assert().failure();
}

#[test]
fn no_subcommand_exits_nonzero() {
    cli().assert().failure();
}

// =============================================================================
// Missing required arguments
// =============================================================================

#[test]
fn tx_submit_missing_sender_exits_nonzero() {
    cli()
        .args(["tx", "submit", "--data", "hello"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--sender"));
}

// =============================================================================
// Static-response commands (exit 0, return canned JSON)
// =============================================================================

#[test]
fn tx_get_returns_not_implemented_json() {
    cli()
        .args(["tx", "get", "deadbeef"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not_implemented"));
}

#[test]
fn tx_list_returns_not_implemented_json() {
    cli()
        .args(["tx", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not_implemented"));
}

// =============================================================================
// NotImplemented error paths (exit non-zero, print error to stderr)
// =============================================================================

#[test]
fn identity_rotate_exits_nonzero() {
    cli()
        .args(["identity", "rotate", "did:disentangle:abc"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("NotImplemented"));
}

#[test]
fn curvature_stats_exits_nonzero() {
    cli()
        .args(["curvature", "stats"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("NotImplemented"));
}

#[test]
fn petname_list_exits_nonzero() {
    cli()
        .args(["petname", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("NotImplemented"));
}

#[test]
fn node_peers_exits_nonzero() {
    cli()
        .args(["node", "peers"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("NotImplemented"));
}

#[test]
fn tx_mass_exits_nonzero() {
    cli()
        .args(["tx", "mass", "deadbeef"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("NotImplemented"));
}

// =============================================================================
// Connection-refused tests (commands that hit the network)
// =============================================================================

#[test]
fn node_status_connection_refused() {
    // Default --node is localhost:3000; nothing should be listening there.
    cli()
        .args(["node", "status"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("RequestFailed"));
}

// =============================================================================
// JSON output format
// =============================================================================

#[test]
fn tx_get_json_format_outputs_valid_json() {
    let output = cli()
        .args(["--format", "json", "tx", "get", "abc123"])
        .output()
        .expect("failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(parsed["status"], "not_implemented");
    assert_eq!(parsed["tx_id"], "abc123");
}
