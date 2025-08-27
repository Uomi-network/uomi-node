//! Pallet TSS migrations module.
//! Each version hop lives in its own file (v1.rs, v2.rs, ...).

pub mod v1;

pub use v1::MigrateV0ToV1;
