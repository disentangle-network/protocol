//! CommonsPool -- Fungible Value Pool with Coherence-Weighted Distribution
//!
//! A CommonsPool holds fungible value and distributes it to agents
//! based on oracle-computed coherence weights. The pool is the protocol's
//! mechanism for translating coherence into external resource claims.
//!
//! Lifecycle:
//! 1. Creator creates pool with a name
//! 2. Anyone deposits value into the pool
//! 3. Oracle query computes distribution weights
//! 4. Pool distribute applies weights to allocate funds
//! 5. Eligible agents claim their allocations

use disentangle_crypto::hash::{sha3_256_multi, Hash256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonsPool {
    pub id: Hash256,
    pub name: String,
    pub description: String,
    pub creator_did: String,
    pub balance: f64,
    pub min_coherence: f64,
    pub active_distribution: Option<Hash256>,
    pub deposits: Vec<PoolDeposit>,
    pub claims: Vec<PoolClaim>,
    pub allocations: std::collections::HashMap<String, f64>,
    pub created_at_depth: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolDeposit {
    pub depositor_did: String,
    pub amount: f64,
    pub source: String,
    pub depth: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolClaim {
    pub claimant_did: String,
    pub amount: f64,
    pub distribution_id: Hash256,
    pub depth: u64,
}

impl CommonsPool {
    pub fn new(
        name: String,
        description: String,
        creator_did: String,
        created_at_depth: u64,
    ) -> Self {
        let id = sha3_256_multi(&[
            b"COMMONS_POOL_V1",
            name.as_bytes(),
            creator_did.as_bytes(),
            &created_at_depth.to_le_bytes(),
        ]);

        Self {
            id,
            name,
            description,
            creator_did,
            balance: 0.0,
            min_coherence: 0.0,
            active_distribution: None,
            deposits: Vec::new(),
            claims: Vec::new(),
            allocations: std::collections::HashMap::new(),
            created_at_depth,
        }
    }

    pub fn deposit(&mut self, depositor_did: String, amount: f64, source: String, depth: u64) {
        self.balance += amount;
        self.deposits.push(PoolDeposit {
            depositor_did,
            amount,
            source,
            depth,
        });
    }

    /// Apply a distribution to allocate pool funds.
    /// Returns per-agent allocations and remaining balance.
    pub fn distribute(
        &mut self,
        distribution_id: Hash256,
        weights: &std::collections::HashMap<String, f64>,
        depth: u64,
    ) -> std::collections::HashMap<String, f64> {
        let distributable = self.balance;
        let mut allocated = std::collections::HashMap::new();

        for (did, weight) in weights {
            let amount = distributable * weight;
            if amount > 0.0 {
                allocated.insert(did.clone(), amount);
                *self.allocations.entry(did.clone()).or_insert(0.0) += amount;
            }
        }

        let total_allocated: f64 = allocated.values().sum();
        self.balance -= total_allocated;
        self.active_distribution = Some(distribution_id);

        let _ = depth; // recorded implicitly via distribution

        allocated
    }

    /// Claim an allocation. Returns the claimed amount.
    pub fn claim(
        &mut self,
        claimant_did: &str,
        distribution_id: Hash256,
        depth: u64,
    ) -> Option<f64> {
        let amount = self.allocations.remove(claimant_did)?;

        self.claims.push(PoolClaim {
            claimant_did: claimant_did.to_string(),
            amount,
            distribution_id,
            depth,
        });

        Some(amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_creation() {
        let pool = CommonsPool::new(
            "Test Pool".to_string(),
            "A test pool".to_string(),
            "did:disentangle:creator".to_string(),
            100,
        );

        assert_eq!(pool.name, "Test Pool");
        assert_eq!(pool.balance, 0.0);
        assert!(pool.deposits.is_empty());
        assert!(pool.claims.is_empty());
    }

    #[test]
    fn test_pool_deposit() {
        let mut pool = CommonsPool::new(
            "Test Pool".to_string(),
            "".to_string(),
            "did:disentangle:creator".to_string(),
            100,
        );

        pool.deposit(
            "did:disentangle:alice".to_string(),
            100.0,
            "grant".to_string(),
            101,
        );
        assert_eq!(pool.balance, 100.0);
        assert_eq!(pool.deposits.len(), 1);

        pool.deposit(
            "did:disentangle:bob".to_string(),
            50.0,
            "donation".to_string(),
            102,
        );
        assert_eq!(pool.balance, 150.0);
        assert_eq!(pool.deposits.len(), 2);
    }

    #[test]
    fn test_pool_distribute() {
        let mut pool = CommonsPool::new(
            "Test Pool".to_string(),
            "".to_string(),
            "did:disentangle:creator".to_string(),
            100,
        );

        pool.deposit(
            "did:disentangle:funder".to_string(),
            100.0,
            "".to_string(),
            101,
        );

        let mut weights = std::collections::HashMap::new();
        weights.insert("did:disentangle:alice".to_string(), 0.6);
        weights.insert("did:disentangle:bob".to_string(), 0.4);

        let dist_id = [42u8; 32];
        let allocated = pool.distribute(dist_id, &weights, 200);

        assert!((allocated["did:disentangle:alice"] - 60.0).abs() < 0.001);
        assert!((allocated["did:disentangle:bob"] - 40.0).abs() < 0.001);
        assert!(pool.balance.abs() < 0.001);
        assert_eq!(pool.active_distribution, Some(dist_id));
    }

    #[test]
    fn test_pool_claim() {
        let mut pool = CommonsPool::new(
            "Test Pool".to_string(),
            "".to_string(),
            "did:disentangle:creator".to_string(),
            100,
        );

        pool.deposit(
            "did:disentangle:funder".to_string(),
            100.0,
            "".to_string(),
            101,
        );

        let mut weights = std::collections::HashMap::new();
        weights.insert("did:disentangle:alice".to_string(), 0.6);
        weights.insert("did:disentangle:bob".to_string(), 0.4);

        let dist_id = [42u8; 32];
        pool.distribute(dist_id, &weights, 200);

        // Alice claims
        let amount = pool.claim("did:disentangle:alice", dist_id, 201);
        assert!(amount.is_some());
        assert!((amount.unwrap() - 60.0).abs() < 0.001);
        assert_eq!(pool.claims.len(), 1);

        // Alice can't claim again
        let amount2 = pool.claim("did:disentangle:alice", dist_id, 202);
        assert!(amount2.is_none());

        // Bob claims
        let amount3 = pool.claim("did:disentangle:bob", dist_id, 203);
        assert!(amount3.is_some());
        assert!((amount3.unwrap() - 40.0).abs() < 0.001);
    }

    #[test]
    fn test_pool_id_deterministic() {
        let pool1 = CommonsPool::new(
            "Test Pool".to_string(),
            "".to_string(),
            "did:disentangle:creator".to_string(),
            100,
        );
        let pool2 = CommonsPool::new(
            "Test Pool".to_string(),
            "".to_string(),
            "did:disentangle:creator".to_string(),
            100,
        );

        assert_eq!(pool1.id, pool2.id);
    }

    #[test]
    fn test_pool_full_lifecycle() {
        let mut pool = CommonsPool::new(
            "Community Fund".to_string(),
            "Rewards active community members".to_string(),
            "did:disentangle:dao".to_string(),
            1000,
        );

        // Multiple deposits
        pool.deposit(
            "did:disentangle:sponsor1".to_string(),
            500.0,
            "initial".to_string(),
            1001,
        );
        pool.deposit(
            "did:disentangle:sponsor2".to_string(),
            500.0,
            "initial".to_string(),
            1002,
        );
        assert_eq!(pool.balance, 1000.0);

        // Distribute based on oracle weights
        let mut weights = std::collections::HashMap::new();
        weights.insert("did:disentangle:worker1".to_string(), 0.5);
        weights.insert("did:disentangle:worker2".to_string(), 0.3);
        weights.insert("did:disentangle:worker3".to_string(), 0.2);

        let dist_id = disentangle_crypto::hash::sha3_256(b"distribution-1");
        let allocations = pool.distribute(dist_id, &weights, 2000);

        assert_eq!(allocations.len(), 3);
        assert!((allocations["did:disentangle:worker1"] - 500.0).abs() < 0.001);
        assert!((allocations["did:disentangle:worker2"] - 300.0).abs() < 0.001);
        assert!((allocations["did:disentangle:worker3"] - 200.0).abs() < 0.001);
        assert!(pool.balance.abs() < 0.001);

        // Workers claim
        for worker in &[
            "did:disentangle:worker1",
            "did:disentangle:worker2",
            "did:disentangle:worker3",
        ] {
            let claimed = pool.claim(worker, dist_id, 2001);
            assert!(claimed.is_some());
        }

        assert_eq!(pool.claims.len(), 3);
        assert!(pool.allocations.is_empty());
    }
}
