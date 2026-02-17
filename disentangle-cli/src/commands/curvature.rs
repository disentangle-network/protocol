use crate::client::{CliError, CliResult, NodeClient};
use crate::output::OutputFormat;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum CurvatureCommands {
    /// Compute curvature between two DIDs
    Compute {
        /// First DID
        did_a: String,

        /// Second DID
        did_b: String,
    },
    /// Show curvature distribution statistics (not yet supported by node)
    Stats,
    /// Get coherence profile for a DID
    Profile {
        /// DID to query
        did: String,
    },
    /// List neighbors of a DID in the identity graph
    Neighbors {
        /// DID to query
        did: String,
    },
}

pub fn handle(cmd: CurvatureCommands, client: &NodeClient, format: &OutputFormat) -> CliResult<()> {
    match cmd {
        CurvatureCommands::Compute { did_a, did_b } => {
            let resp = client.get(&format!("/coherence/curvature/{}/{}", did_a, did_b))?;
            format.print(&resp);
            Ok(())
        }
        CurvatureCommands::Stats => Err(CliError::NotImplemented(
            "Curvature statistics are not yet supported by the node RPC".to_string(),
        )),
        CurvatureCommands::Profile { did } => {
            let resp = client.get(&format!("/coherence/{}", did))?;
            format.print(&resp);
            Ok(())
        }
        CurvatureCommands::Neighbors { did } => {
            let resp = client.get(&format!("/coherence/neighbors/{}", did))?;
            format.print(&resp);
            Ok(())
        }
    }
}
