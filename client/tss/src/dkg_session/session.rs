//! DKG Session Management
//! 
//! This module handles the lifecycle of DKG sessions including creation, 
//! completion, and finalization of the distributed key generation process.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::convert::TryInto;

use frost_ed25519::{
    self as frost,
    keys::dkg::{self, round2},
    Identifier,
};

use crate::types::{
    SessionId, SessionError, SessionManagerError,
    TSSParticipant, TSSPublic
};
use crate::session::dkg_state_manager::DKGSessionState;
use crate::dkghelpers::{Storage, StorageType};
use crate::network::PeerMapper;
use crate::dkg_session::{round1, round2 as dkg_round2};

/// Handles the creation of a new DKG session
/// 
/// This function validates parameters, generates round 1 packages, and initiates the DKG process.
pub fn handle_session_created<S: Storage>(
    session_id: SessionId,
    n: u64,
    t: u64,
    _participants: Vec<TSSParticipant>,
    participant_identifier: Identifier,
    storage: Arc<Mutex<S>>,
    dkg_session_states: Arc<Mutex<std::collections::HashMap<SessionId, DKGSessionState>>>,
) -> Result<(frost_ed25519::keys::dkg::round1::Package, frost_ed25519::keys::dkg::round1::SecretPackage), SessionError> {
    // Validate threshold and participant count
    if t == 0 || n == 0 || t > n {
        log::error!("[TSS] Invalid threshold parameters for DKG session {}: t={}, n={}", session_id, t, n);
        return Err(SessionError::GenericError(format!("Invalid threshold parameters: t={}, n={}", t, n)));
    }
    
    if _participants.len() != n as usize {
        log::error!(
            "[TSS] Mismatch between participant count and n parameter for DKG session {}: {} vs {}",
            session_id, _participants.len(), n
        );
        return Err(SessionError::GenericError(format!(
            "Participant count ({}) doesn't match n parameter ({})",
            _participants.len(), n
        )));
    }
    
    // Use the provided identifier; do not attempt to derive it here
    log::info!(
        "[TSS] Event received from DKG, starting round 1 for session {} with identifier {:?}",
        session_id,
        participant_identifier
    );

    // Generate round 1 package
    let (r1, secret) = match round1::generate_round1_secret_package(
        t.try_into().unwrap_or(u16::MAX),
        n.try_into().unwrap(),
        participant_identifier,
        session_id,
    ) {
        Ok(result) => result,
        Err(e) => {
            log::error!("[TSS] Failed to generate round 1 package for session {}: {:?}", session_id, e);
            return Err(SessionError::GenericError(format!("Failed to generate round 1 package: {:?}", e)));
        }
    };

    // Store secret package
    let mut storage_guard = storage.lock().unwrap();
    if let Err(e) = storage_guard.store_data(
        session_id,
        StorageType::DKGRound1SecretPackage,
        &secret.serialize().unwrap()[..],
        None,
    ) {
        log::error!("[TSS] Failed to store secret package for session {}: {:?}", session_id, e);
        return Err(SessionError::GenericError(format!("Failed to store secret package: {:?}", e)));
    }
    drop(storage_guard);

    // Update session state
    let mut handle_state = dkg_session_states.lock().unwrap();
    handle_state.insert(session_id, DKGSessionState::Round1Initiated);
    drop(handle_state);

    log::debug!("[TSS] DKG session {} created successfully", session_id);
    
    Ok((r1, secret))
}

/// Verifies and completes the DKG process (Part 3)
/// 
/// This function combines all round 2 packages to complete the DKG and generate the final keys.
pub fn verify_and_complete<S: Storage, KS: Storage>(
    session_id: SessionId,
    storage: Arc<Mutex<S>>,
    key_storage: Arc<Mutex<KS>>,
    dkg_session_states: Arc<Mutex<std::collections::HashMap<SessionId, DKGSessionState>>>,
    peer_mapper: Arc<Mutex<PeerMapper>>,
    validator_key: &TSSPublic,
) -> Result<(), SessionManagerError> {
    let storage_guard = storage.lock().unwrap();

    let round2_secret_package = storage_guard.read_secret_package_round2(session_id);
    if let Err(_e) = round2_secret_package {
        log::warn!(
            "[TSS]: Received DKGRound2 for session {} but local round 2 secret package not ready yet.",
            session_id
        );
        return Err(SessionManagerError::Round2SecretPackageNotYetAvailable);
    }
    let round2_secret_package = round2_secret_package.unwrap();

    let n = round2_secret_package.max_signers();

    let round1_packages = storage_guard.fetch_round1_packages(session_id).unwrap();
    let round2_packages = storage_guard.fetch_round2_packages(session_id).unwrap();
    drop(storage_guard); // Release lock

    if round2_packages.keys().len() >= (n - 1).into() {
        match dkg::part3(&round2_secret_package, &round1_packages, &round2_packages) {
            Ok((private_key, public_key)) => {
                let mut peer_mapper_handle = peer_mapper.lock().unwrap();
                let whoami_identifier = peer_mapper_handle.get_identifier_from_account_id(&session_id, validator_key);

                if whoami_identifier.is_none() {
                    log::error!("[TSS] We are not allowed to participate in the signing phase");
                    return Err(SessionManagerError::IdentifierNotFound);
                }
                drop(peer_mapper_handle);

                let mut key_storage_guard = key_storage.lock().unwrap();
                let _ = key_storage_guard.store_data(
                    session_id,
                    StorageType::PubKey,
                    &public_key.serialize().unwrap()[..],
                    Some(&whoami_identifier.unwrap().serialize()),
                );
                if let Err(error) = key_storage_guard.store_data(
                    session_id,
                    StorageType::Key,
                    &private_key.serialize().unwrap()[..],
                    Some(&whoami_identifier.unwrap().serialize()),
                ) {
                    log::error!("[TSS] There was an error storing key {:?}", error);
                }
                drop(key_storage_guard);
                
                log::info!(
                    "[TSS]: DKG Part 3 successful for session {}. Public Key: {:?}",
                    session_id,
                    public_key
                );
                
                // Update session state to KeyGenerated
                let mut session_state_lock = dkg_session_states.lock().unwrap();
                session_state_lock.insert(session_id, DKGSessionState::KeyGenerated);
                drop(session_state_lock); // Release lock
            }
            Err(e) => {
                log::error!(
                    "[TSS]: DKG Part 3 failed for session {}: {:?}",
                    session_id,
                    e
                );
                // Update session state to Failed
                let mut session_state_lock = dkg_session_states.lock().unwrap();
                session_state_lock.insert(session_id, DKGSessionState::Failed);
                drop(session_state_lock);
                
                return Err(SessionManagerError::DkgPart3Failed(format!("{:?}", e)));
            }
        }
    }
    
    Ok(())
}

/// Verifies round 1 packages and starts round 2
/// 
/// This function processes collected round 1 packages and generates round 2 packages.
pub fn verify_and_start_round2<S: Storage>(
    session_id: SessionId,
    storage: Arc<Mutex<S>>,
    dkg_session_states: Arc<Mutex<std::collections::HashMap<SessionId, DKGSessionState>>>,
    data: &crate::types::SessionData,
    round1_packages: BTreeMap<Identifier, dkg::round1::Package>,
) -> Result<BTreeMap<Identifier, round2::Package>, SessionManagerError> {
    let storage_guard = storage.lock().unwrap();
    let round1_secret_package = storage_guard.read_secret_package_round1(session_id);
    drop(storage_guard);

    if round1_secret_package.is_err() {
        log::error!("[TSS] Failed to read round 1 secret package for session {}", session_id);
        return Err(SessionManagerError::Round1SecretPackageNotFound);
    }

    let round1_secret_package = round1_secret_package.unwrap();

    match dkg_round2::round2_verify_round1_participants(
        session_id,
        round1_secret_package,
        &round1_packages,
    ) {
        Ok((round2_secret_package, round2_packages)) => {
            // Store round 2 secret package
            let mut storage_guard = storage.lock().unwrap();
            if let Err(e) = storage_guard.store_data(
                session_id,
                StorageType::DKGRound2SecretPackage,
                &round2_secret_package.serialize().unwrap()[..],
                None,
            ) {
                log::error!("[TSS] Failed to store round 2 secret package for session {}: {:?}", session_id, e);
                return Err(SessionManagerError::StorageError(format!("{:?}", e)));
            }
            drop(storage_guard);

            // Update session state
            let mut session_state_lock = dkg_session_states.lock().unwrap();
            session_state_lock.insert(session_id, DKGSessionState::Round2Initiated);
            drop(session_state_lock);

            log::debug!("[TSS] Round 2 initiated for session {}", session_id);
            Ok(round2_packages)
        }
        Err(e) => {
            log::error!("[TSS] Round 2 verification failed for session {}: {:?}", session_id, e);
            
            // Update session state to Failed
            let mut session_state_lock = dkg_session_states.lock().unwrap();
            session_state_lock.insert(session_id, DKGSessionState::Failed);
            drop(session_state_lock);
            
            Err(SessionManagerError::Round2VerificationFailed(format!("{:?}", e)))
        }
    }
}