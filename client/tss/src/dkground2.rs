use crate::types::SessionId;
use frost_ed25519::{
    self as frost,
    keys::dkg::{self, round2},
    Error, Identifier,
};
use std::collections::BTreeMap;

pub fn round2_verify_round1_participants(
    _session_id: SessionId,
    round1_secret_package: dkg::round1::SecretPackage,
    round1_packages: &BTreeMap<Identifier, dkg::round1::Package>,
) -> Result<(round2::SecretPackage, BTreeMap<Identifier, round2::Package>), Error> {
    // TODO: implement semaphore here
    frost::keys::dkg::part2(round1_secret_package, round1_packages)
}
