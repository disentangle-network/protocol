use clap::Subcommand;
use crate::client::{NodeClient, CliResult, CliError};
use crate::output::OutputFormat;

#[derive(Subcommand)]
pub enum NodeCommands {
    /// Get node status
    Status,
    /// Get DAG graph structure
    Graph,
    /// List connected peers (not yet supported by node)
    Peers,
    /// Show DAG statistics
    DagStats,
    /// Trigger a conflict (debug only)
    TriggerConflict,
}

pub fn handle(cmd: NodeCommands, client: &NodeClient, format: &OutputFormat) -> CliResult<()> {
    match cmd {
        NodeCommands::Status => {
            let resp = client.get("/status")?;
            format.print(&resp);
            Ok(())
        }
        NodeCommands::Graph => {
            let resp = client.get("/graph")?;
            format.print(&resp);
            Ok(())
        }
        NodeCommands::Peers => {
            Err(CliError::NotImplemented(
                "Peer listing is not yet supported by the node RPC".to_string()
            ))
        }
        NodeCommands::DagStats => {
            // Extract stats from the /graph endpoint
            let graph = client.get("/graph")?;
            let stats = serde_json::json!({
                "source": "/graph",
                "total_nodes": graph.get("nodes")
                    .and_then(|n| n.as_array())
                    .map(|a| a.len()),
                "total_edges": graph.get("edges")
                    .and_then(|e| e.as_array())
                    .map(|a| a.len()),
                "tips": graph.get("tips")
                    .and_then(|t| t.as_array())
                    .map(|a| a.len()),
                "raw": graph,
            });
            format.print(&stats);
            Ok(())
        }
        NodeCommands::TriggerConflict => {
            let resp = client.post("/debug/trigger-conflict", &serde_json::json!({}))?;
            format.print(&resp);
            Ok(())
        }
    }
}
