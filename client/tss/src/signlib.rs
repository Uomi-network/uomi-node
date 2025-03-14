use std::collections::BTreeMap;

use frost_ed25519::{
    self as frost,
    keys::KeyPackage,
    round1::{SigningCommitments, SigningNonces},
    Identifier,
};
use rand::thread_rng;

pub fn generate_signing_commitments_and_nonces(
    key_package: KeyPackage,
) -> (SigningNonces, SigningCommitments) {
    let mut rng = thread_rng();

    let (signing_nonces, signing_commitments) =
        frost::round1::commit(key_package.signing_share(), &mut rng);

    (signing_nonces, signing_commitments)
}

pub fn get_signing_package(
    message: &[u8],
    commitments_map: BTreeMap<Identifier, SigningCommitments>,
) -> frost::SigningPackage {
    frost::SigningPackage::new(commitments_map, message)
}
