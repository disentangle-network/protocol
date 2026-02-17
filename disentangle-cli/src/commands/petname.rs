use crate::client::{CliError, CliResult, NodeClient};
use crate::keys;
use crate::output::OutputFormat;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum PetnameCommands {
    /// Set a petname for a DID
    Set {
        /// Petname (human-readable label)
        name: String,

        /// DID to assign this petname to
        did: String,
    },
    /// Resolve a petname to a DID
    Get {
        /// Petname to look up
        name: String,
    },
    /// List all petnames (not yet supported by node)
    List,
    /// Introduce a DID with an edge name (social introduction)
    Introduce {
        /// Introducer DID
        #[arg(long)]
        introducer_did: String,

        /// Introducer signing key (hex). If omitted, loaded from local key storage using --did.
        #[arg(long)]
        introducer_sk_hex: Option<String>,

        /// DID to load signing key from local storage (used when --introducer-sk-hex is omitted)
        #[arg(long)]
        did: Option<String>,

        /// DID being introduced
        #[arg(long)]
        introduced_did: String,

        /// Edge name for the introduction
        #[arg(long)]
        edge_name: String,
    },
}

pub fn handle(cmd: PetnameCommands, client: &NodeClient, format: &OutputFormat) -> CliResult<()> {
    match cmd {
        PetnameCommands::Set { name, did } => {
            let body = serde_json::json!({
                "name": name,
                "did": did,
            });
            let resp = client.post("/petname", &body)?;
            format.print(&resp);
            Ok(())
        }
        PetnameCommands::Get { name } => {
            let resp = client.get(&format!("/petname/{}", name))?;
            format.print(&resp);
            Ok(())
        }
        PetnameCommands::List => Err(CliError::NotImplemented(
            "Petname listing is not yet supported by the node RPC".to_string(),
        )),
        PetnameCommands::Introduce {
            introducer_did,
            introducer_sk_hex,
            did,
            introduced_did,
            edge_name,
        } => {
            let sk_hex = match introducer_sk_hex {
                Some(sk) => sk,
                None => {
                    let key_did = did.as_ref().unwrap_or(&introducer_did);
                    keys::load_key(key_did)?
                        .ok_or_else(|| CliError::KeyNotFound(key_did.clone()))?
                }
            };

            let body = serde_json::json!({
                "introducer_did": introducer_did,
                "introducer_sk_hex": sk_hex,
                "introduced_did": introduced_did,
                "edge_name": edge_name,
            });
            let resp = client.post("/introduction", &body)?;
            format.print(&resp);
            Ok(())
        }
    }
}
