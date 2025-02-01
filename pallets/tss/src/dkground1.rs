use frost_ed25519::{self as frost, keys::dkg, Identifier};
use rand::thread_rng;

use crate::{dkghelpers::{self, store_data}, types::SessionId};


pub fn generate_round1_secret_package(t:u16, n:u16, participant_index:u16, session_id:SessionId) -> Result<(),frost::Error>{

    let mut rng = thread_rng();


    let participant_identifier = participant_index.try_into().expect("should be nonzero");
    let (round1_secret_package, round1_package) =
        frost::keys::dkg::part1(participant_identifier, n, t, &mut rng)?;

    
    // Store the participant's secret package for later use.
    
    store_round1_secret_package(participant_identifier, round1_secret_package, session_id);
    
    // "Send" the round 1 package to all other participants. In this
    // test this is simulated using a BTreeMap; in practice this will be
    // sent through some communication channel.
    for receiver_participant_index in 1..=n {
        if receiver_participant_index == participant_index {
            continue;
        }
        let receiver_participant_identifier: frost::Identifier = receiver_participant_index
            .try_into()
            .expect("should be nonzero");
        
        send_round_1_package_to_receiver(receiver_participant_identifier, round1_package.clone(), session_id);
    }

    Ok(())
}


fn store_round1_secret_package(identifier: Identifier, secret_package:dkg::round1::SecretPackage, session_id:SessionId) {
    let result = secret_package.serialize();

    if let Err(e) = result {
        panic!("{:?}", e);
    }

    let bytes = result.unwrap();

    store_data(session_id, dkghelpers::StorageType::Round1SecretPackage, &bytes, Some(&identifier));
}

fn send_round_1_package_to_receiver(receiver_participant_identifier:Identifier, round1_package: dkg::round1::Package, session_id:SessionId) {

}