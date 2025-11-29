//! EquiX utilities: solving, proof bundling, and replay-protection helpers.
pub mod bundle;
pub mod solver;
pub mod types;

pub use bundle::{derive_replay_tags, EquixProofBundle};
pub use solver::{
    default_base_tag, equix_challenge, equix_check_bits, equix_solve_bundle,
    equix_solve_bundle_auto, equix_solve_parallel_hits, equix_solve_with_bits,
    equix_verify_solution, EquixHitStream, EquixSolveConfig, EquixSolver,
};
pub use types::{EquixHit, EquixProof, EquixSolution};
