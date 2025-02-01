use std::collections::BTreeMap;
use crate::{dkghelpers::{self, store_data, StorageType}, types::SessionId};
use frost_ed25519::{self as frost, keys::dkg::{self, round1::SecretPackage}, Identifier};
use std::fs::File;
use std::io::Write;
pub fn round2_verify_round1_participants(session_id:SessionId,round1_secret_package: dkg::round1::SecretPackage, round1_packages: &BTreeMap<Identifier, dkg::round1::Package>) {
    
    let result = frost::keys::dkg::part2(round1_secret_package, round1_packages);

    if let Err(e) = result {
        println!("Error in round 2: {:?}", e);
        panic!("POSSIBLY BAD ACTOR");
    }

    let(secret_package, packages) = result.unwrap();

    store_round2_packages(session_id, packages);
    store_round2_secret_package(session_id, secret_package);

}

pub fn store_round2_secret_package(session_id:SessionId, secret_package:dkg::round2::SecretPackage) {
    let result = secret_package.serialize();

    if let Err(e) = result {
        panic!("{:?}", e);
    }

    let bytes = result.unwrap();

    store_data(session_id, dkghelpers::StorageType::Round2SecretPackage, &bytes, None);
}

pub fn store_round2_packages(session_id:SessionId,packages:BTreeMap<Identifier, dkg::round2::Package>) {
    for (identifier, package) in packages.iter() {
        let result = package.serialize();

        if let Err(e) = result {
            panic!("Error serializing package for identifier {:?}: {:?}", identifier, e);
        }

        let bytes = result.unwrap();

        store_data(session_id, StorageType::Round2IdentifierPackage, &bytes, Some(identifier));
    }
}
