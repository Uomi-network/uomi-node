//! DKG Round 1 Implementation
//! 
//! This module handles the first round of the FROST DKG protocol.
//! In round 1, each participant generates their secret package and public commitment.

use frost_ed25519::{self as frost, Identifier};
use rand::thread_rng;

use crate::types::SessionId;

/// Generates the round 1 secret package and public commitment for DKG
/// 
/// # Arguments
/// * `t` - Threshold value (minimum signers required)
/// * `n` - Total number of participants
/// * `participant_identifier` - Unique identifier for this participant
/// * `_session_id` - Session identifier (unused but kept for future use)
/// 
/// # Returns
/// A tuple containing the public package to share and the secret package to keep private
pub fn generate_round1_secret_package(
    t: u16,
    n: u16,
    participant_identifier: Identifier,
    _session_id: SessionId,
) -> Result<(frost_ed25519::keys::dkg::round1::Package, frost_ed25519::keys::dkg::round1::SecretPackage), frost::Error> {
    // TODO: implement semaphore here for rate limiting
    
    let mut rng = thread_rng();
    let (round1_secret_package, round1_package) =
        frost::keys::dkg::part1(participant_identifier, n, t, &mut rng)?;

    Ok((round1_package, round1_secret_package))
}