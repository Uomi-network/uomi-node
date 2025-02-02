use std::collections::BTreeMap;

use frost_ed25519::{
    self as frost, round1::SigningCommitments, round2::SignatureShare, Identifier, Signature,
    SigningPackage,
};
use rand::thread_rng;

use crate::{
    dkghelpers::{get_key_package, get_pubkey, get_signing_nonces, store_data},
    types::SessionId,
};

pub fn generate_signing_commitments_and_nonces(session_id: SessionId) {
    let mut rng = thread_rng();

    let key_package = get_key_package(session_id).expect("Error fetching the key package");

    let (signing_nonces, signing_commitments) =
        frost::round1::commit(key_package.signing_share(), &mut rng);

    let serialized_nonces = signing_nonces
        .serialize()
        .expect("Failed to serialize signing nonces");
    store_data(
        session_id,
        crate::dkghelpers::StorageType::SigningNonces,
        &serialized_nonces,
        None,
    )
    .expect("Error storing Signing Nonces");

    send_commitments(session_id, signing_commitments);
}

pub fn send_commitments(
    session_id: SessionId,
    signing_commitments: frost::round1::SigningCommitments,
) {
    // TODO: implement this function
}

pub fn get_signing_package(
    message: &[u8],
    commitments_map: BTreeMap<Identifier, SigningCommitments>,
) -> frost::SigningPackage {
    frost::SigningPackage::new(commitments_map, message)
}

pub fn get_commitments_map(session_id: SessionId) -> BTreeMap<Identifier, SigningCommitments> {
    // TODO implement
    BTreeMap::new()
}
pub fn get_message(session_id: SessionId) -> Vec<u8> {
    vec![].into()
}

pub fn generate_and_send_signature_share(session_id: SessionId, signing_package: SigningPackage) {
    let key_package = get_key_package(session_id).expect("Error fetching the key package");

    let nonces = get_signing_nonces(session_id).expect("Error fetching nonces");

    let signature_share = frost::round2::sign(&signing_package, &nonces, &key_package).unwrap();

    send_signature_share(session_id, signature_share);
}

pub fn send_signature_share(session_id: SessionId, signature_share: SignatureShare) {
    // TODO implement
}

pub fn get_signature_shares(session_id: SessionId) -> BTreeMap<Identifier, SignatureShare> {
    BTreeMap::new()
}

pub fn aggregate_signature_shares(session_id: SessionId) {
    let message = &get_message(session_id);
    let commitments_map = get_commitments_map(session_id);
    let signing_package = get_signing_package(message, commitments_map);

    let signature_shares = get_signature_shares(session_id);

    let pubkey_package = get_pubkey(session_id).unwrap();

    let group_signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)
        .expect("Signature aggregation failed:");

    // Check that the threshold signature can be verified by the group public
    // key (the verification key).
    let is_signature_valid = pubkey_package
        .verifying_key()
        .verify(message, &group_signature)
        .is_ok();
    assert!(is_signature_valid);
}

pub fn verify_signature(session_id: SessionId, group_signature_data: &[u8]) -> bool {
    let message = get_message(session_id);
    let pubkey_package = get_pubkey(session_id).expect("Error fetching public key");

    let group_signature =
        Signature::deserialize(group_signature_data).expect("Error deserializing Signature ");

    pubkey_package
        .verifying_key()
        .verify(&message[..], &group_signature)
        .is_ok()
}
