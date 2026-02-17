use crate::client::{CliError, CliResult, NodeClient};
use crate::output::OutputFormat;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum TxCommands {
    /// Submit a new transaction
    Submit {
        /// Sender identity (for now, a label)
        #[arg(long)]
        sender: String,

        /// Parent transaction IDs (hex, comma-separated)
        #[arg(long, value_delimiter = ',')]
        parents: Vec<String>,

        /// Transaction data
        #[arg(long)]
        data: String,
    },
    /// Get transaction by ID
    Get {
        /// Transaction ID (hex)
        tx_id: String,
    },
    /// List recent transactions
    List {
        /// Maximum number of transactions to show
        #[arg(long, default_value = "10")]
        limit: usize,
    },
    /// Show DAG tips (transactions with no children)
    Tips,
    /// Query the mass of a transaction (not yet supported by node)
    Mass {
        /// Transaction ID (hex)
        tx_id: String,
    },
}

pub fn handle(cmd: TxCommands, client: &NodeClient, format: &OutputFormat) -> CliResult<()> {
    match cmd {
        TxCommands::Submit {
            sender,
            parents,
            data,
        } => {
            let body = serde_json::json!({
                "sender": sender,
                "parents": parents,
                "data": data
            });
            let resp = client.post("/transaction", &body)?;
            format.print(&resp);
            Ok(())
        }
        TxCommands::Get { tx_id } => {
            let resp = serde_json::json!({
                "status": "not_implemented",
                "tx_id": tx_id,
                "message": "GET /transaction/:id endpoint not yet implemented on node"
            });
            format.print(&resp);
            Ok(())
        }
        TxCommands::List { limit } => {
            let resp = serde_json::json!({
                "status": "not_implemented",
                "limit": limit,
                "message": "Transaction listing endpoint not yet implemented",
                "hint": "Use 'disentangle tx tips' or 'disentangle node graph' to inspect DAG"
            });
            format.print(&resp);
            Ok(())
        }
        TxCommands::Tips => {
            // GET /graph returns the full graph; extract tips from it
            let graph = client.get("/graph")?;
            if let Some(tips) = graph.get("tips") {
                let resp = serde_json::json!({
                    "tips": tips,
                });
                format.print(&resp);
            } else {
                // Fall back to showing the full graph if no tips field
                let resp = serde_json::json!({
                    "message": "Tips extracted from /graph endpoint",
                    "graph": graph,
                });
                format.print(&resp);
            }
            Ok(())
        }
        TxCommands::Mass { tx_id } => Err(CliError::NotImplemented(format!(
            "Transaction mass query for {} is not yet supported by the node RPC",
            tx_id
        ))),
    }
}
