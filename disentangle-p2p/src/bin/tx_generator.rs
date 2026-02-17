//! Transaction Generator for Disentangle Node
//!
//! Generates synthetic transaction traffic to a running node via RPC.
//! Useful for demonstrating protocol operation and creating meaningful DAG structure.
//!
//! # Usage
//!
//! Start a Disentangle node first:
//! ```bash
//! cargo run -p disentangle-p2p --bin disentangle-node -- 9000 3000
//! ```
//!
//! Then run the generator in a separate terminal:
//! ```bash
//! # Basic usage (1 tx/s, 3 senders, unlimited duration)
//! cargo run -p disentangle-p2p --bin tx-generator
//!
//! # Custom rate and sender count
//! cargo run -p disentangle-p2p --bin tx-generator -- --rate 5.0 --senders 10
//!
//! # Generate exactly 100 transactions
//! cargo run -p disentangle-p2p --bin tx-generator -- --count 100
//!
//! # Connect to remote node
//! cargo run -p disentangle-p2p --bin tx-generator -- --node-url http://192.168.1.100:3000
//! ```
//!
//! # Features
//!
//! - **Multi-sender simulation**: Rotates through N distinct sender identities to simulate
//!   multi-party activity and create diverse DAG topology
//! - **Smart parent selection**: Fetches current tips from /graph endpoint and randomly
//!   selects 2-4 parents to create realistic DAG branching
//! - **Exponential backoff**: Automatically retries on network errors with increasing delays
//! - **Periodic reporting**: Shows DAG growth, transaction rate, and node status every 10s
//! - **Graceful shutdown**: Press Ctrl+C to stop cleanly
//!
//! # RPC Endpoints Used
//!
//! - `GET /graph` - Fetch current tips for parent selection
//! - `POST /transaction` - Submit new transactions
//! - `GET /status` - Periodic health and metrics reporting

use clap::Parser;
use rand::seq::SliceRandom;
use rand::Rng;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(name = "tx-generator")]
#[command(about = "Generate synthetic transaction traffic for Disentangle nodes", long_about = None)]
struct Args {
    /// Node RPC URL
    #[arg(long, default_value = "http://localhost:3000")]
    node_url: String,

    /// Transactions per second
    #[arg(long, default_value = "1.0")]
    rate: f64,

    /// Total transaction count (0 = unlimited)
    #[arg(long, default_value = "0")]
    count: usize,

    /// Number of unique sender identities
    #[arg(long, default_value = "3")]
    senders: usize,
}

#[derive(Serialize)]
struct SubmitTxRequest {
    sender: String,
    parents: Vec<String>,
    data: String,
}

#[derive(Deserialize)]
struct TxResponse {
    success: bool,
    tx_id: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct StatusResponse {
    peer_id: String,
    peer_count: usize,
    dag_size: usize,
    pending_txs: usize,
    tips: Vec<String>,
    max_depth: u64,
    conflicts_resolved: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct GraphResponse {
    nodes: Vec<serde_json::Value>,
    edges: Vec<serde_json::Value>,
    tips: Vec<String>,
    conflicts: Vec<String>,
}

/// Exponential backoff retry strategy
struct Backoff {
    current: Duration,
    max: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self {
            current: Duration::from_millis(100),
            max: Duration::from_secs(30),
        }
    }

    fn wait(&mut self) {
        thread::sleep(self.current);
        self.current = std::cmp::min(self.current * 2, self.max);
    }

    fn reset(&mut self) {
        self.current = Duration::from_millis(100);
    }
}

/// Transaction generator state
struct Generator {
    client: Client,
    node_url: String,
    senders: Vec<String>,
    sender_sequences: Vec<usize>,
    current_sender: usize,
    total_sent: usize,
    total_errors: usize,
    start_time: Instant,
    backoff: Backoff,
    last_status_check: Instant,
    last_dag_size: usize,
}

impl Generator {
    fn new(node_url: String, num_senders: usize) -> Self {
        let senders: Vec<String> = (0..num_senders)
            .map(|i| format!("sender-{}", i))
            .collect();
        let sender_sequences = vec![0; num_senders];

        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to build HTTP client"),
            node_url,
            senders,
            sender_sequences,
            current_sender: 0,
            total_sent: 0,
            total_errors: 0,
            start_time: Instant::now(),
            backoff: Backoff::new(),
            last_status_check: Instant::now(),
            last_dag_size: 0,
        }
    }

    /// Fetch current tips from node
    fn fetch_tips(&mut self) -> Result<Vec<String>, String> {
        let url = format!("{}/graph", self.node_url);
        match self.client.get(&url).send() {
            Ok(response) => {
                self.backoff.reset();
                match response.json::<GraphResponse>() {
                    Ok(graph) => Ok(graph.tips),
                    Err(e) => Err(format!("Failed to parse graph response: {}", e)),
                }
            }
            Err(e) => {
                Err(format!("Failed to fetch graph: {}", e))
            }
        }
    }

    /// Select 2-4 random parents from available tips
    fn select_parents(&self, tips: &[String]) -> Vec<String> {
        if tips.is_empty() {
            return Vec::new();
        }

        let mut rng = rand::thread_rng();
        let parent_count = if tips.len() == 1 {
            1
        } else if tips.len() < 4 {
            rng.gen_range(2..=tips.len())
        } else {
            rng.gen_range(2..=4)
        };

        tips.choose_multiple(&mut rng, parent_count)
            .cloned()
            .collect()
    }

    /// Generate and submit one transaction
    fn send_transaction(&mut self) -> Result<String, String> {
        // Fetch current tips
        let tips = self.fetch_tips()?;

        if tips.is_empty() {
            return Err("No tips available (DAG may be empty)".to_string());
        }

        // Select parents
        let parents = self.select_parents(&tips);

        // Get current sender and increment sequence
        let sender = self.senders[self.current_sender].clone();
        let seq = self.sender_sequences[self.current_sender];
        self.sender_sequences[self.current_sender] += 1;

        // Rotate to next sender for multi-party simulation
        self.current_sender = (self.current_sender + 1) % self.senders.len();

        // Build transaction data
        let data = format!("tx-{}-{}", sender, seq);
        let request = SubmitTxRequest {
            sender: sender.clone(),
            parents,
            data,
        };

        // Submit transaction
        let url = format!("{}/transaction", self.node_url);
        match self.client.post(&url).json(&request).send() {
            Ok(response) => {
                self.backoff.reset();
                match response.json::<TxResponse>() {
                    Ok(tx_resp) => {
                        if tx_resp.success {
                            self.total_sent += 1;
                            Ok(tx_resp.tx_id.unwrap_or_else(|| "unknown".to_string()))
                        } else {
                            self.total_errors += 1;
                            Err(tx_resp.error.unwrap_or_else(|| "Unknown error".to_string()))
                        }
                    }
                    Err(e) => {
                        self.total_errors += 1;
                        Err(format!("Failed to parse response: {}", e))
                    }
                }
            }
            Err(e) => {
                self.total_errors += 1;
                Err(format!("Request failed: {}", e))
            }
        }
    }

    /// Check node status and print periodic report
    fn check_status(&mut self) {
        let url = format!("{}/status", self.node_url);
        match self.client.get(&url).send() {
            Ok(response) => {
                if let Ok(status) = response.json::<StatusResponse>() {
                    let elapsed = self.start_time.elapsed().as_secs();
                    let rate = if elapsed > 0 {
                        self.total_sent as f64 / elapsed as f64
                    } else {
                        0.0
                    };

                    println!("\n=== Status Report ===");
                    println!("  Uptime: {}s", elapsed);
                    println!("  Transactions sent: {} ({:.2} tx/s)", self.total_sent, rate);
                    println!("  Errors: {}", self.total_errors);
                    println!("  DAG size: {} (Δ: +{})",
                        status.dag_size,
                        status.dag_size.saturating_sub(self.last_dag_size)
                    );
                    println!("  Pending: {}", status.pending_txs);
                    println!("  Tips: {}", status.tips.len());
                    println!("  Max depth: {}", status.max_depth);
                    println!("  Peers: {}", status.peer_count);
                    println!("  Conflicts resolved: {}", status.conflicts_resolved.len());
                    println!("====================\n");

                    self.last_dag_size = status.dag_size;
                }
            }
            Err(_) => {
                // Silently skip status check if node is unreachable
            }
        }
        self.last_status_check = Instant::now();
    }

    /// Main generation loop
    fn run(&mut self, rate: f64, max_count: usize) {
        println!("Transaction Generator Starting");
        println!("  Node: {}", self.node_url);
        println!("  Rate: {} tx/s", rate);
        println!("  Senders: {}", self.senders.len());
        println!("  Target count: {}", if max_count == 0 { "unlimited".to_string() } else { max_count.to_string() });
        println!("\nPress Ctrl+C to stop.\n");

        let interval = Duration::from_secs_f64(1.0 / rate);
        let status_interval = Duration::from_secs(10);
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        // Setup Ctrl+C handler
        ctrlc::set_handler(move || {
            println!("\n\nShutting down gracefully...");
            r.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl+C handler");

        // Wait for node to be ready
        println!("Waiting for node to be ready...");
        loop {
            let url = format!("{}/status", self.node_url);
            if self.client.get(&url).send().is_ok() {
                println!("Node is ready!\n");
                break;
            }
            print!(".");
            std::io::Write::flush(&mut std::io::stdout()).expect("Failed to flush stdout");
            self.backoff.wait();

            if !running.load(Ordering::SeqCst) {
                println!("\nCancelled.");
                return;
            }
        }
        self.backoff.reset();

        // Main loop
        let mut next_tx = Instant::now();
        loop {
            if !running.load(Ordering::SeqCst) {
                break;
            }

            if max_count > 0 && self.total_sent >= max_count {
                println!("\nTarget count reached: {} transactions sent", self.total_sent);
                break;
            }

            // Send transaction
            if Instant::now() >= next_tx {
                match self.send_transaction() {
                    Ok(tx_id) => {
                        println!("[{}] ✓ Sent tx {} (total: {}, errors: {})",
                            self.total_sent,
                            tx_id,
                            self.total_sent,
                            self.total_errors
                        );
                    }
                    Err(e) => {
                        println!("[{}] ✗ Error: {} (retrying...)", self.total_errors, e);
                        self.backoff.wait();
                        continue; // Don't advance next_tx on error
                    }
                }
                next_tx = Instant::now() + interval;
            }

            // Periodic status check
            if self.last_status_check.elapsed() >= status_interval {
                self.check_status();
            }

            // Sleep briefly to avoid busy loop
            thread::sleep(Duration::from_millis(50));
        }

        // Final status report
        println!("\n=== Final Report ===");
        self.check_status();
        println!("Generator stopped.");
    }
}

fn main() {
    let args = Args::parse();

    if args.rate <= 0.0 {
        eprintln!("Error: Rate must be greater than 0");
        std::process::exit(1);
    }

    if args.senders == 0 {
        eprintln!("Error: Must have at least 1 sender");
        std::process::exit(1);
    }

    let mut generator = Generator::new(args.node_url, args.senders);
    generator.run(args.rate, args.count);
}
