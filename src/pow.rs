use crate::error::{Error, VerifyError};

/// Configuration for a proof-of-work algorithm.
///
/// Implementations typically at least expose a difficulty parameter,
/// but can include additional algorithm-specific fields as needed.
pub trait PowConfig: Clone {
    /// Return the abstract difficulty for this configuration.
    ///
    /// For EquiX backends this is interpreted as the required number of leading
    /// zero bits in the difficulty hash; other algorithms are free to map this
    /// to their own difficulty model.
    fn difficulty(&self) -> u32;
}

/// A single proof-of-work solution.
pub trait PowProof {
    /// The logical identifier for this proof within the search space.
    fn id(&self) -> u64;
}

/// A bundle of proofs produced for a single master challenge.
pub trait PowBundle {
    /// The proof type contained in this bundle.
    type Proof: PowProof;

    /// The configuration type associated with this bundle.
    type Config: PowConfig;

    /// Return the proofs in this bundle.
    fn proofs(&self) -> &[Self::Proof];

    /// Return the configuration for this bundle.
    fn config(&self) -> &Self::Config;

    /// Return the master challenge for this bundle.
    fn master_challenge(&self) -> &[u8; 32];

    /// Number of proofs in this bundle.
    fn len(&self) -> usize {
        self.proofs().len()
    }

    /// Whether this bundle contains no proofs.
    fn is_empty(&self) -> bool {
        self.proofs().is_empty()
    }

    /// Insert a new proof into the bundle.
    ///
    /// Implementations should enforce any invariants such as uniqueness and ordering.
    fn insert_proof(&mut self, proof: Self::Proof) -> Result<(), VerifyError>;

    /// Strictly verify this bundle, including all contained proofs and structural invariants.
    fn verify_strict(&self) -> Result<(), VerifyError>;
}

/// A proof-of-work engine capable of solving and resuming bundles.
pub trait PowEngine {
    /// The bundle type produced by this engine.
    type Bundle: PowBundle;

    /// Solve a new bundle for the given master challenge.
    fn solve_bundle(&mut self, master_challenge: [u8; 32]) -> Result<Self::Bundle, Error>;

    /// Resume solving an existing bundle using the engine's configured target.
    ///
    /// The engine's own configuration (for example its `required_proofs` field)
    /// determines how many proofs are required after resuming.
    fn resume(&mut self, existing: Self::Bundle) -> Result<Self::Bundle, Error>;
}
