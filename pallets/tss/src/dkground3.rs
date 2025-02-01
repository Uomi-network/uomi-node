use std::collections::BTreeMap;

use frost_ed25519::{keys::dkg, Identifier, Error};

use crate::{dkghelpers::{self, store_data}, types::SessionId};
pub fn fetch_round1_packages(session_id: SessionId) -> BTreeMap<Identifier, dkg::round1::Package> {
    BTreeMap::new()
}

pub fn fetch_round2_packages(session_id: SessionId) -> BTreeMap<Identifier, dkg::round2::Package> {
    BTreeMap::new()
}

pub fn fetch_round2_secret_packages(session_id: SessionId) -> dkg::round2::SecretPackage {
    let bytes: Vec<u8> = vec![];
    dkg::round2::SecretPackage::deserialize(&bytes).unwrap()
}



pub fn round3(session_id:SessionId)->Result<(), Error> {
    let round1_packages = fetch_round1_packages(session_id);
    let round2_secret_package = fetch_round2_secret_packages(session_id);
    let round2_packages = fetch_round2_packages(session_id);

    let (key_package, public_key_package) = dkg::part3(&round2_secret_package, &round1_packages, &round2_packages)?;


    // store key package and public key package
    // need to fix the paths.
    store_data(session_id, dkghelpers::StorageType::Key, &key_package.serialize()?, None);
    store_data(session_id, dkghelpers::StorageType::PubKey, &public_key_package.serialize()?, None);
    Ok(())
}
