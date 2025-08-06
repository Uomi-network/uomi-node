//! DKG Round 2 Implementation
//! 
//! This module handles the second round of the FROST DKG protocol.
//! In round 2, participants verify round 1 packages and generate round 2 packages.

use crate::types::SessionId;
use frost_ed25519::{
    self as frost,
    keys::dkg::{self, round2},
    Error, Identifier,
};
use std::collections::BTreeMap;

/// Verifies round 1 participants and generates round 2 packages
/// 
/// # Arguments
/// * `_session_id` - Session identifier (unused but kept for future use)
/// * `round1_secret_package` - Our secret package from round 1
/// * `round1_packages` - Public packages from all participants in round 1
/// 
/// # Returns
/// A tuple containing our round 2 secret package and round 2 packages to send to each participant
pub fn round2_verify_round1_participants(
    _session_id: SessionId,
    round1_secret_package: dkg::round1::SecretPackage,
    round1_packages: &BTreeMap<Identifier, dkg::round1::Package>,
) -> Result<(round2::SecretPackage, BTreeMap<Identifier, round2::Package>), Error> {
    // TODO: implement semaphore here for rate limiting
    frost::keys::dkg::part2(round1_secret_package, round1_packages)
}