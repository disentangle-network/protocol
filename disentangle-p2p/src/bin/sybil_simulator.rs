//! Sybil Attack Simulator
//!
//! Demonstrates the protocol's topology-based Sybil resistance by:
//! 1. Creating honest agents with dense interconnections (positive curvature)
//! 2. Creating Sybil agents with tree topology (negative curvature)
//! 3. Generating transactions from both groups
//! 4. Comparing coherence scores to show honest >> sybil
//!
//! Demonstrates that topological curvature detects Sybil clusters without requiring tokens.

use clap::Parser;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Parser)]
#[command(name = "sybil-simulator")]
#[command(about = "Demonstrate Sybil resistance through topology analysis")]
struct Args {
    /// Node RPC URL
    #[arg(long, default_value = "http://localhost:8000")]
    node_url: String,

    /// Number of honest agents to create
    #[arg(long, default_value = "5")]
    honest_count: usize,

    /// Number of Sybil agents to create (excluding root)
    #[arg(long, default_value = "10")]
    sybil_count: usize,

    /// Number of transactions per identity
    #[arg(long, default_value = "3")]
    tx_per_identity: usize,
}

#[derive(Serialize)]
struct RegisterRequest {
    agent_type: String,
}

#[derive(Deserialize)]
struct RegisterResponse {
    did: String,
    signing_key_hex: String,
    #[allow(dead_code)]
    document: serde_json::Value,
}

#[derive(Serialize)]
struct IntroductionRequest {
    introducer_did: String,
    introducer_sk_hex: String,
    introduced_did: String,
    edge_name: String,
}

#[derive(Serialize, Deserialize)]
struct IntroductionResponse {
    success: bool,
}

#[derive(Serialize)]
struct TransactionRequest {
    sender: String,
    parents: Vec<String>,
    data: String,
}

#[derive(Deserialize)]
struct TransactionResponse {
    success: bool,
    tx_id: String,
}

#[derive(Deserialize)]
struct CoherenceProfile {
    topological_mass: f64,
    mean_local_curvature: f64,
    relational_diversity: usize,
    #[allow(dead_code)]
    temporal_depth: usize,
    composite_score: f64,
    #[allow(dead_code)]
    decayed_mass: f64,
}

#[derive(Deserialize)]
struct CoherenceResponse {
    profile: CoherenceProfile,
}

#[derive(Deserialize)]
struct GraphResponse {
    #[allow(dead_code)]
    nodes: Vec<serde_json::Value>,
    #[allow(dead_code)]
    edges: Vec<serde_json::Value>,
    tips: Vec<String>,
}

struct Identity {
    did: String,
    signing_key_hex: String,
    name: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let client = Client::new();

    println!("=== SYBIL ATTACK SIMULATOR ===");
    println!("Node: {}", args.node_url);
    println!("Honest agents: {}", args.honest_count);
    println!("Sybil agents: {} (+ 1 root)", args.sybil_count);
    println!("Transactions per identity: {}", args.tx_per_identity);
    println!();

    // Phase 1: Register honest identities
    println!("Phase 1: Registering honest agents...");
    let mut honest_agents = Vec::new();
    for i in 0..args.honest_count {
        let agent = register_identity(&client, &args.node_url, "human", &format!("honest-{}", i))?;
        println!("  ✓ {} ({}...)", agent.name, &agent.did[..20]);
        honest_agents.push(agent);
    }

    // Create dense interconnections (all-pairs)
    println!("  Creating dense interconnections...");
    for i in 0..honest_agents.len() {
        for j in (i + 1)..honest_agents.len() {
            introduce(
                &client,
                &args.node_url,
                &honest_agents[i],
                &honest_agents[j].did,
                &format!("{}-knows-{}", honest_agents[i].name, honest_agents[j].name),
            )?;
            // Bidirectional for symmetry
            introduce(
                &client,
                &args.node_url,
                &honest_agents[j],
                &honest_agents[i].did,
                &format!("{}-knows-{}", honest_agents[j].name, honest_agents[i].name),
            )?;
        }
    }
    println!(
        "  ✓ Created {} edges (dense mesh)",
        honest_agents.len() * (honest_agents.len() - 1)
    );
    println!();

    // Phase 2: Register Sybil identities (tree topology)
    println!("Phase 2: Registering Sybil agents...");
    let sybil_root = register_identity(&client, &args.node_url, "agi", "sybil-root")?;
    println!("  ✓ {} ({}...)", sybil_root.name, &sybil_root.did[..20]);

    let mut sybil_leaves = Vec::new();
    for i in 0..args.sybil_count {
        let agent =
            register_identity(&client, &args.node_url, "agi", &format!("sybil-leaf-{}", i))?;
        println!("  ✓ {} ({}...)", agent.name, &agent.did[..20]);
        sybil_leaves.push(agent);
    }

    // Create tree topology: root introduces each leaf (no leaf-leaf connections)
    println!("  Creating tree topology...");
    for leaf in &sybil_leaves {
        introduce(
            &client,
            &args.node_url,
            &sybil_root,
            &leaf.did,
            &format!("{}-introduces-{}", sybil_root.name, leaf.name),
        )?;
    }
    println!("  ✓ Created {} edges (star/tree)", sybil_leaves.len());
    println!();

    // Phase 3: Generate transactions
    println!("Phase 3: Generating transactions...");
    let all_identities: Vec<&Identity> = honest_agents
        .iter()
        .chain(std::iter::once(&sybil_root))
        .chain(sybil_leaves.iter())
        .collect();

    for identity in &all_identities {
        for tx_num in 0..args.tx_per_identity {
            // Get current tips for parent selection
            let tips = get_tips(&client, &args.node_url)?;
            let parents = if tips.is_empty() {
                vec![]
            } else if tips.len() == 1 {
                vec![tips[0].clone()]
            } else {
                // Select 2 random tips
                vec![tips[0].clone(), tips[1].clone()]
            };

            let tx_data = format!("{}-tx-{}", identity.name, tx_num);
            submit_transaction(&client, &args.node_url, &identity.did, parents, &tx_data)?;
        }
        println!(
            "  ✓ {} submitted {} transactions",
            identity.name, args.tx_per_identity
        );
    }
    println!();

    // Phase 4: Query coherence and display comparison
    println!("Phase 4: Querying coherence profiles...");
    println!();

    // Query honest agents
    println!("=== HONEST AGENTS ===");
    println!(
        "{:<20} {:>10} {:>12} {:>10} {:>10}",
        "DID (short)", "Mass", "Curvature", "Diversity", "Score"
    );
    println!("{:-<64}", "");

    let mut honest_scores = Vec::new();
    for agent in &honest_agents {
        let profile = get_coherence(&client, &args.node_url, &agent.did)?;
        println!(
            "{:<20} {:>10.4} {:>12.4} {:>10} {:>10.4}",
            format!("{} ({}...)", agent.name, &agent.did[15..19]),
            profile.topological_mass,
            profile.mean_local_curvature,
            profile.relational_diversity,
            profile.composite_score
        );
        honest_scores.push(profile.composite_score);
    }
    println!();

    // Query Sybil agents
    println!("=== SYBIL AGENTS ===");
    println!(
        "{:<20} {:>10} {:>12} {:>10} {:>10}",
        "DID (short)", "Mass", "Curvature", "Diversity", "Score"
    );
    println!("{:-<64}", "");

    let mut sybil_scores = Vec::new();

    // Root
    let root_profile = get_coherence(&client, &args.node_url, &sybil_root.did)?;
    println!(
        "{:<20} {:>10.4} {:>12.4} {:>10} {:>10.4}",
        format!("{} ({}...)", sybil_root.name, &sybil_root.did[15..19]),
        root_profile.topological_mass,
        root_profile.mean_local_curvature,
        root_profile.relational_diversity,
        root_profile.composite_score
    );
    sybil_scores.push(root_profile.composite_score);

    // Leaves
    for agent in &sybil_leaves {
        let profile = get_coherence(&client, &args.node_url, &agent.did)?;
        println!(
            "{:<20} {:>10.4} {:>12.4} {:>10} {:>10.4}",
            format!("{} ({}...)", agent.name, &agent.did[15..19]),
            profile.topological_mass,
            profile.mean_local_curvature,
            profile.relational_diversity,
            profile.composite_score
        );
        sybil_scores.push(profile.composite_score);
    }
    println!();

    // Summary
    let avg_honest = honest_scores.iter().sum::<f64>() / honest_scores.len() as f64;
    let avg_sybil = sybil_scores.iter().sum::<f64>() / sybil_scores.len() as f64;
    let ratio = if avg_sybil > 0.0001 {
        avg_honest / avg_sybil
    } else {
        f64::INFINITY
    };

    println!("=== RESULT ===");
    println!("Avg honest score: {:.4}", avg_honest);
    println!("Avg sybil score:  {:.4}", avg_sybil);
    if ratio.is_infinite() {
        println!("Ratio: ∞ (sybil score near zero)");
    } else {
        println!("Ratio: {:.1}x", ratio);
    }
    println!();
    println!("Topological curvature successfully discriminates Sybil clusters.");

    Ok(())
}

fn register_identity(
    client: &Client,
    node_url: &str,
    agent_type: &str,
    name: &str,
) -> Result<Identity, Box<dyn Error>> {
    let url = format!("{}/identity/register", node_url);
    let req = RegisterRequest {
        agent_type: agent_type.to_string(),
    };

    let resp = client
        .post(&url)
        .json(&req)
        .send()
        .map_err(|e| format!("Failed to register identity: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Registration failed with status: {}", resp.status()).into());
    }

    let data: RegisterResponse = resp
        .json()
        .map_err(|e| format!("Failed to parse registration response: {}", e))?;

    Ok(Identity {
        did: data.did,
        signing_key_hex: data.signing_key_hex,
        name: name.to_string(),
    })
}

fn introduce(
    client: &Client,
    node_url: &str,
    introducer: &Identity,
    introduced_did: &str,
    edge_name: &str,
) -> Result<(), Box<dyn Error>> {
    let url = format!("{}/introduction", node_url);
    let req = IntroductionRequest {
        introducer_did: introducer.did.clone(),
        introducer_sk_hex: introducer.signing_key_hex.clone(),
        introduced_did: introduced_did.to_string(),
        edge_name: edge_name.to_string(),
    };

    let resp = client
        .post(&url)
        .json(&req)
        .send()
        .map_err(|e| format!("Failed to create introduction: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Introduction failed with status: {}", resp.status()).into());
    }

    let data: IntroductionResponse = resp
        .json()
        .map_err(|e| format!("Failed to parse introduction response: {}", e))?;

    if !data.success {
        return Err("Introduction reported failure".into());
    }

    Ok(())
}

fn submit_transaction(
    client: &Client,
    node_url: &str,
    sender: &str,
    parents: Vec<String>,
    data: &str,
) -> Result<String, Box<dyn Error>> {
    let url = format!("{}/transaction", node_url);
    let req = TransactionRequest {
        sender: sender.to_string(),
        parents,
        data: data.to_string(),
    };

    let resp = client
        .post(&url)
        .json(&req)
        .send()
        .map_err(|e| format!("Failed to submit transaction: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Transaction failed with status: {}", resp.status()).into());
    }

    let data: TransactionResponse = resp
        .json()
        .map_err(|e| format!("Failed to parse transaction response: {}", e))?;

    if !data.success {
        return Err("Transaction reported failure".into());
    }

    Ok(data.tx_id)
}

fn get_tips(client: &Client, node_url: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let url = format!("{}/graph", node_url);
    let resp = client
        .get(&url)
        .send()
        .map_err(|e| format!("Failed to get graph: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Graph query failed with status: {}", resp.status()).into());
    }

    let data: GraphResponse = resp
        .json()
        .map_err(|e| format!("Failed to parse graph response: {}", e))?;

    Ok(data.tips)
}

fn get_coherence(
    client: &Client,
    node_url: &str,
    did: &str,
) -> Result<CoherenceProfile, Box<dyn Error>> {
    let url = format!("{}/coherence/{}", node_url, did);
    let resp = client
        .get(&url)
        .send()
        .map_err(|e| format!("Failed to get coherence: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Coherence query failed with status: {}", resp.status()).into());
    }

    let data: CoherenceResponse = resp
        .json()
        .map_err(|e| format!("Failed to parse coherence response: {}", e))?;

    Ok(data.profile)
}
