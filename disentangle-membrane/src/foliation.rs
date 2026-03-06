use crate::level::LevelTemporality;
use std::collections::HashMap;

/// Unique identifier for a foliation leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeafId(pub u64);

/// Node identifier (independent of disentangle-crypto's NodeId).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; 32]);

/// Leaf classification for a set of nodes based on level-temporality.
///
/// Not consensus — local computation each node can do independently from
/// observed peer LevelTemporality values. Nodes with similar LT are grouped
/// into the same leaf; nodes with divergent LT are separated.
pub struct Foliation {
    /// Members of each leaf.
    leaves: HashMap<LeafId, Vec<NodeId>>,
    /// Which leaf each node belongs to.
    assignments: HashMap<NodeId, LeafId>,
    /// Representative LT for each leaf (first node assigned).
    representatives: HashMap<LeafId, LevelTemporality>,
    /// Next leaf ID to assign.
    next_leaf_id: u64,
    /// Maximum level gap for same-leaf assignment.
    level_epsilon: u32,
    /// Maximum temporal gap for same-leaf assignment.
    temporal_epsilon: f64,
}

impl Foliation {
    pub fn new(level_epsilon: u32, temporal_epsilon: f64) -> Self {
        Foliation {
            leaves: HashMap::new(),
            assignments: HashMap::new(),
            representatives: HashMap::new(),
            next_leaf_id: 0,
            level_epsilon,
            temporal_epsilon,
        }
    }

    /// Classify a node into a leaf based on its level-temporality.
    /// If the node was previously classified, it is removed from its old
    /// leaf and reclassified (supporting evolution).
    pub fn classify(&mut self, node: NodeId, lt: LevelTemporality) -> LeafId {
        // Remove from old leaf if previously assigned
        if let Some(&old_leaf) = self.assignments.get(&node) {
            if let Some(members) = self.leaves.get_mut(&old_leaf) {
                members.retain(|n| n != &node);
                // Clean up empty leaves
                if members.is_empty() {
                    self.leaves.remove(&old_leaf);
                    self.representatives.remove(&old_leaf);
                }
            }
            self.assignments.remove(&node);
        }

        // Find an existing leaf whose representative is within epsilon
        let matching_leaf = self.representatives.iter().find(|(_, rep_lt)| {
            let (level_gap, temporal_gap) = lt.gap(rep_lt);
            level_gap <= self.level_epsilon && temporal_gap <= self.temporal_epsilon
        });

        let leaf_id = if let Some((&lid, _)) = matching_leaf {
            lid
        } else {
            // Create new leaf
            let lid = LeafId(self.next_leaf_id);
            self.next_leaf_id += 1;
            self.leaves.insert(lid, Vec::new());
            self.representatives.insert(lid, lt);
            lid
        };

        self.leaves.get_mut(&leaf_id).unwrap().push(node);
        self.assignments.insert(node, leaf_id);
        leaf_id
    }

    /// Check whether two nodes are in the same leaf.
    pub fn same_leaf(&self, a: &NodeId, b: &NodeId) -> bool {
        match (self.assignments.get(a), self.assignments.get(b)) {
            (Some(la), Some(lb)) => la == lb,
            _ => false,
        }
    }

    /// Get the members of a leaf.
    pub fn leaf_members(&self, leaf: LeafId) -> &[NodeId] {
        self.leaves.get(&leaf).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Compute the level-temporality gap between two leaves using their
    /// representative LT values.
    pub fn inter_leaf_gap(&self, a: LeafId, b: LeafId) -> (u32, f64) {
        match (self.representatives.get(&a), self.representatives.get(&b)) {
            (Some(lt_a), Some(lt_b)) => lt_a.gap(lt_b),
            _ => (u32::MAX, f64::MAX),
        }
    }

    /// Get the leaf assignment for a node, if any.
    pub fn assignment(&self, node: &NodeId) -> Option<LeafId> {
        self.assignments.get(node).copied()
    }

    /// Total number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
}
