use clap::Subcommand;
use crate::client::{NodeClient, CliResult, CliError};
use crate::keys;
use crate::output::OutputFormat;

/// Resolve signing key: use explicit --signing-key-hex if given, otherwise load from --did key storage.
fn resolve_signing_key(signing_key_hex: Option<String>, did: Option<&String>) -> CliResult<String> {
    match signing_key_hex {
        Some(sk) => Ok(sk),
        None => {
            let did = did.ok_or(CliError::MissingKey)?;
            keys::load_key(did)?
                .ok_or_else(|| CliError::KeyNotFound(did.clone()))
        }
    }
}

#[derive(Subcommand)]
pub enum CapCommands {
    /// Create a new capability
    Create {
        /// Issuer DID
        #[arg(long)]
        issuer_did: String,

        /// Issuer signing key (hex). If omitted, loaded from local key storage using --did.
        #[arg(long)]
        signing_key_hex: Option<String>,

        /// DID to load signing key from local storage (used when --signing-key-hex is omitted)
        #[arg(long)]
        did: Option<String>,

        /// Subject JSON (e.g. '{"Resource":"did:disentangle:..."}')
        #[arg(long)]
        subject: String,

        /// Constraints JSON array (e.g. '[{"TimeWindow":{"start":0,"end":9999999}}]')
        #[arg(long, default_value = "[]")]
        constraints: String,

        /// Whether the capability can be further delegated
        #[arg(long, default_value = "false")]
        delegatable: bool,
    },
    /// Delegate an existing capability to another DID
    Delegate {
        /// Capability ID (hex)
        #[arg(long)]
        capability_id: String,

        /// Delegator DID
        #[arg(long)]
        delegator_did: String,

        /// Delegator signing key (hex). If omitted, loaded from local key storage using --did.
        #[arg(long)]
        delegator_sk_hex: Option<String>,

        /// DID to load signing key from local storage (used when --delegator-sk-hex is omitted)
        #[arg(long)]
        did: Option<String>,

        /// Delegatee DID (who receives the delegation)
        #[arg(long)]
        delegatee_did: String,
    },
    /// Invoke a capability
    Invoke {
        /// Capability ID (hex)
        #[arg(long)]
        capability_id: String,

        /// Invoker DID
        #[arg(long)]
        invoker_did: String,
    },
    /// Revoke a capability
    Revoke {
        /// Capability ID (hex)
        #[arg(long)]
        capability_id: String,

        /// Revoker DID
        #[arg(long)]
        revoker_did: String,

        /// Revocation scope (single, subtree, or all)
        #[arg(long, default_value = "single")]
        scope: String,
    },
    /// List capabilities for a DID
    List {
        /// DID to list capabilities for
        did: String,
    },
}

pub fn handle(cmd: CapCommands, client: &NodeClient, format: &OutputFormat) -> CliResult<()> {
    match cmd {
        CapCommands::Create {
            issuer_did,
            signing_key_hex,
            did,
            subject,
            constraints,
            delegatable,
        } => {
            let sk_hex = resolve_signing_key(signing_key_hex, did.as_ref().or(Some(&issuer_did)))?;

            let subject_val: serde_json::Value = serde_json::from_str(&subject)
                .map_err(|e| CliError::NodeError(
                    format!("Invalid subject JSON: {}", e)
                ))?;
            let constraints_val: serde_json::Value = serde_json::from_str(&constraints)
                .map_err(|e| CliError::NodeError(
                    format!("Invalid constraints JSON: {}", e)
                ))?;

            let body = serde_json::json!({
                "issuer_did": issuer_did,
                "signing_key_hex": sk_hex,
                "subject": subject_val,
                "constraints": constraints_val,
                "delegatable": delegatable,
            });
            let resp = client.post("/capability/create", &body)?;
            format.print(&resp);
            Ok(())
        }
        CapCommands::Delegate {
            capability_id,
            delegator_did,
            delegator_sk_hex,
            did,
            delegatee_did,
        } => {
            let sk_hex = resolve_signing_key(delegator_sk_hex, did.as_ref().or(Some(&delegator_did)))?;

            let body = serde_json::json!({
                "capability_id_hex": capability_id,
                "delegator_did": delegator_did,
                "delegator_sk_hex": sk_hex,
                "delegatee_did": delegatee_did,
            });
            let resp = client.post("/capability/delegate", &body)?;
            format.print(&resp);
            Ok(())
        }
        CapCommands::Invoke {
            capability_id,
            invoker_did,
        } => {
            let body = serde_json::json!({
                "capability_id_hex": capability_id,
                "invoker_did": invoker_did,
            });
            let resp = client.post("/capability/invoke", &body)?;
            format.print(&resp);
            Ok(())
        }
        CapCommands::Revoke {
            capability_id,
            revoker_did,
            scope,
        } => {
            let body = serde_json::json!({
                "capability_id_hex": capability_id,
                "revoker_did": revoker_did,
                "scope": scope,
            });
            let resp = client.post("/capability/revoke", &body)?;
            format.print(&resp);
            Ok(())
        }
        CapCommands::List { did } => {
            let resp = client.get(&format!("/capability/by-did/{}", did))?;
            format.print(&resp);
            Ok(())
        }
    }
}
