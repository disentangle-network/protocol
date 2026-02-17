//! Topology Event Detection
//!
//! Protocol-detected phase changes (merge/split) emitted via EventBus.
//! These are NOT actions - the geometry creates them.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Minimum edge weight for neighborhood membership
pub const W_MIN: f64 = 0.1;

/// Merge threshold for boundary curvature
pub const MERGE_THRESHOLD: f64 = 0.2;

/// Persistence window for event detection (consecutive checks)
pub const PERSISTENCE_WINDOW: u32 = 3;

/// A detected neighborhood (connected component)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Neighborhood {
    /// Deterministic hash from sorted member DIDs
    pub id: String,
    /// Member DIDs
    pub members: Vec<String>,
    /// Total topological mass
    pub total_mass: f64,
    /// Mean internal curvature
    pub mean_curvature: f64,
}

impl Neighborhood {
    /// Compute deterministic ID from members
    pub fn compute_id(members: &[String]) -> String {
        let mut sorted = members.to_vec();
        sorted.sort();
        let combined = sorted.join("|");

        use disentangle_crypto::hash::sha3_256;
        let hash = sha3_256(combined.as_bytes());
        hex::encode(&hash[..8]) // Use first 8 bytes for readability
    }

    pub fn new(members: Vec<String>, total_mass: f64, mean_curvature: f64) -> Self {
        let id = Self::compute_id(&members);
        Self {
            id,
            members,
            total_mass,
            mean_curvature,
        }
    }
}

/// Detect neighborhoods from identity graph
///
/// Returns connected components where all edges have weight >= W_MIN
pub fn detect_neighborhoods(
    graph: &HashMap<String, HashMap<String, f64>>, // did -> (neighbor_did -> curvature)
    masses: &HashMap<String, f64>,
) -> Vec<Neighborhood> {
    let mut visited = HashSet::new();
    let mut neighborhoods = Vec::new();

    for did in graph.keys() {
        if visited.contains(did) {
            continue;
        }

        // BFS to find connected component
        let mut component = Vec::new();
        let mut queue = vec![did.clone()];
        let mut local_visited = HashSet::new();

        while let Some(current) = queue.pop() {
            if local_visited.contains(&current) {
                continue;
            }
            local_visited.insert(current.clone());
            component.push(current.clone());

            // Add neighbors with sufficient edge weight
            if let Some(neighbors) = graph.get(&current) {
                for (neighbor, curvature) in neighbors {
                    if *curvature >= W_MIN && !local_visited.contains(neighbor) {
                        queue.push(neighbor.clone());
                    }
                }
            }
        }

        visited.extend(local_visited);

        // Compute neighborhood stats
        let total_mass: f64 = component
            .iter()
            .map(|did| masses.get(did).copied().unwrap_or(0.0))
            .sum();

        // Compute mean curvature of internal edges
        let mut curvature_sum = 0.0;
        let mut edge_count = 0;
        for did in &component {
            if let Some(neighbors) = graph.get(did) {
                for (neighbor, curvature) in neighbors {
                    if component.contains(neighbor) {
                        curvature_sum += curvature;
                        edge_count += 1;
                    }
                }
            }
        }
        let mean_curvature = if edge_count > 0 {
            curvature_sum / edge_count as f64
        } else {
            0.0
        };

        neighborhoods.push(Neighborhood::new(component, total_mass, mean_curvature));
    }

    neighborhoods
}

/// Detect potential merge events between neighborhoods
///
/// Returns pairs of neighborhoods with high boundary curvature
pub fn detect_merge_candidates(
    neighborhoods: &[Neighborhood],
    graph: &HashMap<String, HashMap<String, f64>>,
) -> Vec<(String, String, f64)> {
    let mut candidates = Vec::new();

    for i in 0..neighborhoods.len() {
        for j in (i + 1)..neighborhoods.len() {
            let n1 = &neighborhoods[i];
            let n2 = &neighborhoods[j];

            // Find boundary edges between these neighborhoods
            let mut boundary_curvatures = Vec::new();

            for did1 in &n1.members {
                if let Some(neighbors) = graph.get(did1) {
                    for did2 in &n2.members {
                        if let Some(curvature) = neighbors.get(did2) {
                            boundary_curvatures.push(*curvature);
                        }
                    }
                }
            }

            if !boundary_curvatures.is_empty() {
                let mean_boundary_curvature: f64 =
                    boundary_curvatures.iter().sum::<f64>() / boundary_curvatures.len() as f64;

                if mean_boundary_curvature >= MERGE_THRESHOLD {
                    candidates.push((n1.id.clone(), n2.id.clone(), mean_boundary_curvature));
                }
            }
        }
    }

    candidates
}

/// Detect potential split events within a neighborhood
///
/// Returns neighborhoods that have weak internal edges that would disconnect them
pub fn detect_split_candidates(
    neighborhood: &Neighborhood,
    graph: &HashMap<String, HashMap<String, f64>>,
) -> Option<(Vec<String>, f64)> {
    // Find edges at minimum weight (epsilon threshold)
    let epsilon = W_MIN;
    let mut weak_edges = Vec::new();

    for did in &neighborhood.members {
        if let Some(neighbors) = graph.get(did) {
            for (neighbor, curvature) in neighbors {
                if neighborhood.members.contains(neighbor) && (*curvature - epsilon).abs() < 0.01 {
                    weak_edges.push((did.clone(), neighbor.clone(), *curvature));
                }
            }
        }
    }

    if weak_edges.is_empty() {
        return None;
    }

    // Simulate removing weak edges and check if component disconnects
    // For now, just return the weak edges if any exist
    // Full implementation would require graph connectivity check
    let mean_weak_curvature: f64 =
        weak_edges.iter().map(|(_, _, c)| c).sum::<f64>() / weak_edges.len() as f64;

    // Return potential split if weak edges exist
    if !weak_edges.is_empty() {
        Some((neighborhood.members.clone(), mean_weak_curvature))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neighborhood_detection_single_component() {
        let mut graph = HashMap::new();
        let mut masses = HashMap::new();

        // Create triangle: A-B-C with positive curvature
        let mut a_neighbors = HashMap::new();
        a_neighbors.insert("B".to_string(), 0.5);
        a_neighbors.insert("C".to_string(), 0.5);
        graph.insert("A".to_string(), a_neighbors);

        let mut b_neighbors = HashMap::new();
        b_neighbors.insert("A".to_string(), 0.5);
        b_neighbors.insert("C".to_string(), 0.5);
        graph.insert("B".to_string(), b_neighbors);

        let mut c_neighbors = HashMap::new();
        c_neighbors.insert("A".to_string(), 0.5);
        c_neighbors.insert("B".to_string(), 0.5);
        graph.insert("C".to_string(), c_neighbors);

        masses.insert("A".to_string(), 10.0);
        masses.insert("B".to_string(), 20.0);
        masses.insert("C".to_string(), 30.0);

        let neighborhoods = detect_neighborhoods(&graph, &masses);

        assert_eq!(neighborhoods.len(), 1);
        assert_eq!(neighborhoods[0].members.len(), 3);
        assert_eq!(neighborhoods[0].total_mass, 60.0);
    }

    #[test]
    fn test_neighborhood_detection_weak_edge() {
        let mut graph = HashMap::new();
        let mut masses = HashMap::new();

        // A-B with weak edge (below threshold), C-D with strong edge
        let mut a_neighbors = HashMap::new();
        a_neighbors.insert("B".to_string(), 0.05); // Below W_MIN
        graph.insert("A".to_string(), a_neighbors);

        let mut b_neighbors = HashMap::new();
        b_neighbors.insert("A".to_string(), 0.05);
        graph.insert("B".to_string(), b_neighbors);

        let mut c_neighbors = HashMap::new();
        c_neighbors.insert("D".to_string(), 0.5);
        graph.insert("C".to_string(), c_neighbors);

        let mut d_neighbors = HashMap::new();
        d_neighbors.insert("C".to_string(), 0.5);
        graph.insert("D".to_string(), d_neighbors);

        masses.insert("A".to_string(), 10.0);
        masses.insert("B".to_string(), 10.0);
        masses.insert("C".to_string(), 20.0);
        masses.insert("D".to_string(), 20.0);

        let neighborhoods = detect_neighborhoods(&graph, &masses);

        // A and B should be separate (weak edge), C-D together
        assert_eq!(neighborhoods.len(), 3);
    }

    #[test]
    fn test_merge_candidate_detection() {
        let mut graph = HashMap::new();

        // Two neighborhoods with strong boundary edge
        let mut a_neighbors = HashMap::new();
        a_neighbors.insert("B".to_string(), 0.5);
        a_neighbors.insert("C".to_string(), 0.3); // Boundary edge to neighborhood 2
        graph.insert("A".to_string(), a_neighbors);

        let mut b_neighbors = HashMap::new();
        b_neighbors.insert("A".to_string(), 0.5);
        graph.insert("B".to_string(), b_neighbors);

        let mut c_neighbors = HashMap::new();
        c_neighbors.insert("A".to_string(), 0.3);
        c_neighbors.insert("D".to_string(), 0.5);
        graph.insert("C".to_string(), c_neighbors);

        let mut d_neighbors = HashMap::new();
        d_neighbors.insert("C".to_string(), 0.5);
        graph.insert("D".to_string(), d_neighbors);

        let n1 = Neighborhood::new(vec!["A".to_string(), "B".to_string()], 30.0, 0.5);
        let n2 = Neighborhood::new(vec!["C".to_string(), "D".to_string()], 40.0, 0.5);

        let candidates = detect_merge_candidates(&[n1, n2], &graph);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].2, 0.3); // Mean boundary curvature
    }

    #[test]
    fn test_neighborhood_id_deterministic() {
        let members1 = vec!["A".to_string(), "B".to_string(), "C".to_string()];
        let members2 = vec!["C".to_string(), "A".to_string(), "B".to_string()];

        let id1 = Neighborhood::compute_id(&members1);
        let id2 = Neighborhood::compute_id(&members2);

        assert_eq!(id1, id2);
    }
}
