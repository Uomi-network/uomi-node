use frost_ed25519::{self as frost, Identifier};
use rand::thread_rng;

use crate::types::SessionId;

pub fn generate_round1_secret_package(
    t: u16,
    n: u16,
    participant_identifier: Identifier,
    _session_id: SessionId,
) -> Result<(frost_ed25519::keys::dkg::round1::Package, frost_ed25519::keys::dkg::round1::SecretPackage), frost::Error> {

    // TODO: implement semaphore here

    let mut rng = thread_rng();
    let (round1_secret_package, round1_package) =
        frost::keys::dkg::part1(participant_identifier, n, t, &mut rng)?;

    Ok((round1_package, round1_secret_package))
}

