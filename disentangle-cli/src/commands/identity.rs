use crate::client::{CliError, CliResult, NodeClient};
use crate::keys;
use crate::output::OutputFormat;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum IdentityCommands {
    /// Register a new DID
    Create {
        /// Agent type (human or agi)
        #[arg(long, default_value = "human")]
        agent_type: String,

        /// Display name (optional)
        #[arg(long)]
        display_name: Option<String>,
    },
    /// Show identity info
    Show {
        /// DID to look up
        did: String,
    },
    /// List all registered identities
    List,
    /// Rotate keys for an identity (not yet supported by the node)
    Rotate {
        /// DID to rotate keys for
        did: String,
    },
}

pub fn handle(cmd: IdentityCommands, client: &NodeClient, format: &OutputFormat) -> CliResult<()> {
    match cmd {
        IdentityCommands::Create {
            agent_type,
            display_name,
        } => {
            let body = serde_json::json!({
                "agent_type": agent_type,
                "display_name": display_name.unwrap_or_default(),
            });
            let resp = client.post("/identity/register", &body)?;
            format.print(&resp);

            // Auto-save key to local storage if the response contains both did and signing_key_hex
            if let (Some(did), Some(sk)) = (
                resp.get("did").and_then(|v| v.as_str()),
                resp.get("signing_key_hex").and_then(|v| v.as_str()),
            ) {
                match keys::save_key(did, sk) {
                    Ok(()) => {
                        println!("Key saved to ~/.disentangle/keys/");
                    }
                    Err(e) => {
                        eprintln!("Warning: could not save key locally: {}", e);
                    }
                }
            }

            Ok(())
        }
        IdentityCommands::Show { did } => {
            let resp = client.get(&format!("/identity/{}", did))?;
            format.print(&resp);
            Ok(())
        }
        IdentityCommands::List => {
            let resp = client.get("/identity")?;
            format.print(&resp);

            // Also show locally stored keys
            match keys::list_stored_dids() {
                Ok(dids) if !dids.is_empty() => {
                    println!("\nLocally stored keys:");
                    for did in &dids {
                        println!("  {}", did);
                    }
                }
                Ok(_) => {
                    println!("\nNo locally stored keys.");
                }
                Err(e) => {
                    eprintln!("\nWarning: could not read local key storage: {}", e);
                }
            }

            Ok(())
        }
        IdentityCommands::Rotate { did } => Err(CliError::NotImplemented(format!(
            "Key rotation for DID {} is not yet supported by the node RPC",
            did
        ))),
    }
}
