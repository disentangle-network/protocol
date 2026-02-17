use clap::{Parser, Subcommand};

mod client;
mod commands;
mod keys;
mod output;

use client::NodeClient;
use output::OutputFormat;

#[derive(Parser)]
#[command(name = "disentangle")]
#[command(about = "CLI for the Disentangle Protocol")]
#[command(version)]
struct Cli {
    /// Node URL to connect to
    #[arg(long, default_value = "http://localhost:3000", global = true)]
    node: String,

    /// Output format
    #[arg(long, default_value = "human", global = true)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Identity operations
    Identity {
        #[command(subcommand)]
        command: commands::identity::IdentityCommands,
    },
    /// Transaction operations
    Tx {
        #[command(subcommand)]
        command: commands::tx::TxCommands,
    },
    /// Curvature operations
    Curvature {
        #[command(subcommand)]
        command: commands::curvature::CurvatureCommands,
    },
    /// Capability operations
    Cap {
        #[command(subcommand)]
        command: commands::cap::CapCommands,
    },
    /// Petname operations
    Petname {
        #[command(subcommand)]
        command: commands::petname::PetnameCommands,
    },
    /// Governance operations
    Gov {
        #[command(subcommand)]
        command: commands::gov::GovCommands,
    },
    /// Node operations
    Node {
        #[command(subcommand)]
        command: commands::node::NodeCommands,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let client = NodeClient::new(&cli.node);

    match cli.command {
        Commands::Identity { command } => {
            commands::identity::handle(command, &client, &cli.format)?;
        }
        Commands::Tx { command } => {
            commands::tx::handle(command, &client, &cli.format)?;
        }
        Commands::Curvature { command } => {
            commands::curvature::handle(command, &client, &cli.format)?;
        }
        Commands::Cap { command } => {
            commands::cap::handle(command, &client, &cli.format)?;
        }
        Commands::Petname { command } => {
            commands::petname::handle(command, &client, &cli.format)?;
        }
        Commands::Gov { command } => {
            commands::gov::handle(command, &client, &cli.format)?;
        }
        Commands::Node { command } => {
            commands::node::handle(command, &client, &cli.format)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Helper: attempt to parse CLI args; returns Ok(Cli) or Err.
    fn try_parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    // -- Valid subcommand parsing --

    #[test]
    fn parse_identity_create_defaults() {
        let cli = try_parse(&["disentangle", "identity", "create"]).unwrap();
        assert_eq!(cli.node, "http://localhost:3000");
        assert!(matches!(cli.command, Commands::Identity { .. }));
    }

    #[test]
    fn parse_identity_create_with_options() {
        let cli = try_parse(&[
            "disentangle", "identity", "create",
            "--agent-type", "agi",
            "--display-name", "TestBot",
        ]).unwrap();
        if let Commands::Identity { command } = cli.command {
            match command {
                commands::identity::IdentityCommands::Create { agent_type, display_name } => {
                    assert_eq!(agent_type, "agi");
                    assert_eq!(display_name, Some("TestBot".to_string()));
                }
                _ => panic!("Expected Create subcommand"),
            }
        } else {
            panic!("Expected Identity command");
        }
    }

    #[test]
    fn parse_identity_show() {
        let cli = try_parse(&["disentangle", "identity", "show", "did:disentangle:abc"]).unwrap();
        if let Commands::Identity { command } = cli.command {
            match command {
                commands::identity::IdentityCommands::Show { did } => {
                    assert_eq!(did, "did:disentangle:abc");
                }
                _ => panic!("Expected Show subcommand"),
            }
        } else {
            panic!("Expected Identity command");
        }
    }

    #[test]
    fn parse_identity_list() {
        let cli = try_parse(&["disentangle", "identity", "list"]).unwrap();
        assert!(matches!(cli.command, Commands::Identity { .. }));
    }

    #[test]
    fn parse_tx_submit() {
        let cli = try_parse(&[
            "disentangle", "tx", "submit",
            "--sender", "alice",
            "--parents", "aabb,ccdd",
            "--data", "hello world",
        ]).unwrap();
        if let Commands::Tx { command } = cli.command {
            match command {
                commands::tx::TxCommands::Submit { sender, parents, data } => {
                    assert_eq!(sender, "alice");
                    assert_eq!(parents, vec!["aabb", "ccdd"]);
                    assert_eq!(data, "hello world");
                }
                _ => panic!("Expected Submit subcommand"),
            }
        } else {
            panic!("Expected Tx command");
        }
    }

    #[test]
    fn parse_tx_tips() {
        let cli = try_parse(&["disentangle", "tx", "tips"]).unwrap();
        assert!(matches!(cli.command, Commands::Tx { .. }));
    }

    #[test]
    fn parse_curvature_compute() {
        let cli = try_parse(&["disentangle", "curvature", "compute", "did:a", "did:b"]).unwrap();
        if let Commands::Curvature { command } = cli.command {
            match command {
                commands::curvature::CurvatureCommands::Compute { did_a, did_b } => {
                    assert_eq!(did_a, "did:a");
                    assert_eq!(did_b, "did:b");
                }
                _ => panic!("Expected Compute subcommand"),
            }
        } else {
            panic!("Expected Curvature command");
        }
    }

    #[test]
    fn parse_node_status() {
        let cli = try_parse(&["disentangle", "node", "status"]).unwrap();
        assert!(matches!(cli.command, Commands::Node { .. }));
    }

    #[test]
    fn parse_node_graph() {
        let cli = try_parse(&["disentangle", "node", "graph"]).unwrap();
        assert!(matches!(cli.command, Commands::Node { .. }));
    }

    #[test]
    fn parse_petname_set() {
        let cli = try_parse(&["disentangle", "petname", "set", "alice", "did:disentangle:abc"]).unwrap();
        if let Commands::Petname { command } = cli.command {
            match command {
                commands::petname::PetnameCommands::Set { name, did } => {
                    assert_eq!(name, "alice");
                    assert_eq!(did, "did:disentangle:abc");
                }
                _ => panic!("Expected Set subcommand"),
            }
        } else {
            panic!("Expected Petname command");
        }
    }

    #[test]
    fn parse_gov_list() {
        let cli = try_parse(&["disentangle", "gov", "list"]).unwrap();
        assert!(matches!(cli.command, Commands::Gov { .. }));
    }

    #[test]
    fn parse_cap_list() {
        let cli = try_parse(&["disentangle", "cap", "list", "did:disentangle:xyz"]).unwrap();
        if let Commands::Cap { command } = cli.command {
            match command {
                commands::cap::CapCommands::List { did } => {
                    assert_eq!(did, "did:disentangle:xyz");
                }
                _ => panic!("Expected List subcommand"),
            }
        } else {
            panic!("Expected Cap command");
        }
    }

    // -- Global options --

    #[test]
    fn parse_custom_node_url() {
        let cli = try_parse(&[
            "disentangle", "--node", "http://mynode:8080",
            "node", "status",
        ]).unwrap();
        assert_eq!(cli.node, "http://mynode:8080");
    }

    #[test]
    fn parse_json_format() {
        let cli = try_parse(&[
            "disentangle", "--format", "json",
            "node", "status",
        ]).unwrap();
        assert!(matches!(cli.format, OutputFormat::Json));
    }

    #[test]
    fn parse_human_format_explicit() {
        let cli = try_parse(&[
            "disentangle", "--format", "human",
            "node", "status",
        ]).unwrap();
        assert!(matches!(cli.format, OutputFormat::Human));
    }

    // -- Invalid inputs --

    #[test]
    fn reject_unknown_subcommand() {
        let result = try_parse(&["disentangle", "foobar"]);
        assert!(result.is_err());
    }

    #[test]
    fn reject_missing_subcommand() {
        let result = try_parse(&["disentangle"]);
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_format() {
        let result = try_parse(&["disentangle", "--format", "xml", "node", "status"]);
        assert!(result.is_err());
    }

    #[test]
    fn reject_identity_show_missing_did() {
        let result = try_parse(&["disentangle", "identity", "show"]);
        assert!(result.is_err());
    }

    #[test]
    fn reject_tx_submit_missing_required_args() {
        // --sender and --data are required
        let result = try_parse(&["disentangle", "tx", "submit"]);
        assert!(result.is_err());
    }

    #[test]
    fn reject_curvature_compute_missing_args() {
        // Requires two DIDs
        let result = try_parse(&["disentangle", "curvature", "compute", "did:a"]);
        assert!(result.is_err());
    }
}
