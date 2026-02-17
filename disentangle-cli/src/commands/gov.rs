use clap::Subcommand;
use crate::client::{NodeClient, CliResult, CliError};
use crate::keys;
use crate::output::OutputFormat;

#[derive(Subcommand)]
pub enum GovCommands {
    /// Submit a governance proposal
    Propose {
        /// Proposer DID
        #[arg(long)]
        proposer_did: String,

        /// Signing key (hex). If omitted, loaded from local key storage using --did.
        #[arg(long)]
        signing_key_hex: Option<String>,

        /// DID to load signing key from local storage (used when --signing-key-hex is omitted)
        #[arg(long)]
        did: Option<String>,

        /// Proposal type (parameter, policy, upgrade)
        #[arg(long, value_name = "TYPE")]
        r#type: String,

        /// Parameter name (required for parameter proposals)
        #[arg(long)]
        parameter: Option<String>,

        /// Parameter value (required for parameter proposals)
        #[arg(long)]
        value: Option<String>,

        /// Proposal description
        #[arg(long)]
        description: String,

        /// Voting duration in blocks
        #[arg(long, default_value = "1000")]
        duration: u64,
    },
    /// Vote on a proposal
    Vote {
        /// Proposal ID (hex)
        #[arg(long)]
        proposal_id: String,

        /// Voter DID
        #[arg(long)]
        voter_did: String,

        /// Signing key (hex). If omitted, loaded from local key storage using --did.
        #[arg(long)]
        signing_key_hex: Option<String>,

        /// DID to load signing key from local storage (used when --signing-key-hex is omitted)
        #[arg(long)]
        did: Option<String>,

        /// Vote: for, against, or abstain
        #[arg(long, value_parser = ["for", "against", "abstain"])]
        vote: String,
    },
    /// List governance proposals
    List {
        /// Filter by status (active/passed/rejected/expired)
        #[arg(long)]
        status: Option<String>,
    },
    /// Show details for a specific proposal
    Show {
        /// Proposal ID (hex)
        proposal_id: String,
    },
}

pub fn handle(cmd: GovCommands, client: &NodeClient, format: &OutputFormat) -> CliResult<()> {
    match cmd {
        GovCommands::Propose {
            proposer_did,
            signing_key_hex,
            did,
            r#type,
            parameter,
            value,
            description,
            duration,
        } => {
            let sk_hex = match signing_key_hex {
                Some(sk) => sk,
                None => {
                    let key_did = did.as_ref().unwrap_or(&proposer_did);
                    keys::load_key(key_did)?
                        .ok_or_else(|| CliError::KeyNotFound(key_did.clone()))?
                }
            };

            let body = serde_json::json!({
                "proposer_did": proposer_did,
                "signing_key_hex": sk_hex,
                "proposal_type": r#type,
                "parameter": parameter,
                "value": value,
                "description": description,
                "duration_blocks": duration,
            });
            let resp = client.post("/governance/propose", &body)?;
            format.print(&resp);
            Ok(())
        }
        GovCommands::Vote {
            proposal_id,
            voter_did,
            signing_key_hex,
            did,
            vote,
        } => {
            let sk_hex = match signing_key_hex {
                Some(sk) => sk,
                None => {
                    let key_did = did.as_ref().unwrap_or(&voter_did);
                    keys::load_key(key_did)?
                        .ok_or_else(|| CliError::KeyNotFound(key_did.clone()))?
                }
            };

            let body = serde_json::json!({
                "proposal_id": proposal_id,
                "voter_did": voter_did,
                "signing_key_hex": sk_hex,
                "vote": vote,
            });
            let resp = client.post("/governance/vote", &body)?;
            format.print(&resp);
            Ok(())
        }
        GovCommands::List { status } => {
            let path = match &status {
                Some(s) => format!("/governance/proposals?status={}", s),
                None => "/governance/proposals".to_string(),
            };
            let resp = client.get(&path)?;
            format.print(&resp);
            Ok(())
        }
        GovCommands::Show { proposal_id } => {
            let resp = client.get(&format!("/governance/{}", proposal_id))?;
            format.print(&resp);
            Ok(())
        }
    }
}
