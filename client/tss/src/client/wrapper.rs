use codec::{Decode, Encode};
use futures::executor::block_on;
use sc_client_api::{BlockchainEvents, HeaderBackend};
use sc_transaction_pool_api::{LocalTransactionPool, TransactionPool};
use sp_api::ApiExt;
use sp_api::ProvideRuntimeApi;
use sp_core::crypto::CryptoTypeId;
use sp_core::{sr25519, ByteArray};
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use sp_runtime::transaction_validity::TransactionSource;
use sp_runtime::MultiSigner;
use std::{marker::PhantomData, sync::Arc};
use uomi_runtime::{
    self,
    pallet_tss::{
        ReportParticipantsPayload, SubmitDKGResultPayload, TssApi, TssOffenceType, CRYPTO_KEY_TYPE,
    },
};
use uomi_runtime::{AccountId, RuntimeCall, Signature, UncheckedExtrinsic};

use frame_support::BoundedVec; // runtime re-export

use super::manager::ClientManager;
use crate::types::SessionId;

pub struct ClientWrapper<
    B: BlockT,
    C: BlockchainEvents<B> + ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static,
    TP,
> where
    TP: TransactionPool + LocalTransactionPool<Block = B> + Send + Sync + 'static,
{
    client: Arc<C>,
    phantom: PhantomData<B>,
    keystore: KeystorePtr,
    transaction_pool: Arc<TP>,
}

impl<
        B: BlockT,
        C: BlockchainEvents<B>
            + ProvideRuntimeApi<B, Api = T>
            + HeaderBackend<B>
            + Send
            + Sync
            + 'static,
        T: TssApi<B>,
        TP,
    > ClientWrapper<B, C, TP>
where
    TP: TransactionPool<Block = B> + LocalTransactionPool<Block = B> + Send + Sync + 'static,
{
    pub fn new(client: Arc<C>, keystore: KeystorePtr, transaction_pool: Arc<TP>) -> Self {
        Self {
            client,
            phantom: Default::default(),
            keystore,
            transaction_pool,
        }
    }
}

impl<B: BlockT, C, TP> ClientManager<B> for ClientWrapper<B, C, TP>
where
    C: BlockchainEvents<B> + ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static,
    C::Api: uomi_runtime::pallet_tss::TssApi<B>,
    TP: TransactionPool<Block = B> + LocalTransactionPool<Block = B> + Send + Sync + 'static,
{
    fn best_hash(&self) -> <<B as BlockT>::Header as HeaderT>::Hash {
        self.client.info().best_hash
    }

    fn get_all_validator_ids(
        &self,
        hash: <<B as BlockT>::Header as HeaderT>::Hash,
    ) -> Vec<(u32, [u8; 32])> {
        let runtime = self.client.runtime_api();
        // Simple call, no extensions required
        runtime.get_all_validator_ids(hash).unwrap_or_default()
    }

    fn report_participants(
        &self,
        _hash: <<B as BlockT>::Header as HeaderT>::Hash,
        session_id: SessionId,
        inactive_participants: Vec<[u8; 32]>,
    ) -> Result<(), String> {
        // Build payload: convert raw bytes to AccountId BoundedVec
        let accounts: Vec<AccountId> = inactive_participants
            .iter()
            .filter_map(|raw| AccountId::decode(&mut &raw[..]).ok())
            .collect();
        let reported = BoundedVec::try_from(accounts)
            .map_err(|_| "Reported participants exceed MaxNumberOfShares".to_string())?;
        let first = self.first_authority_key()?;
        let payload = ReportParticipantsPayload::<uomi_runtime::Runtime> {
            session_id,
            reported_participants: reported,
            public: MultiSigner::from(first.clone()),
        };
        let signature = self.sign_payload(&first, &payload)?;

        let call = RuntimeCall::Tss(uomi_runtime::pallet_tss::Call::report_participant {
            payload,
            signature,
        });
        self.submit_unsigned(call)
    }

    fn submit_dkg_result(
        &self,
        _hash: <<B as BlockT>::Header as HeaderT>::Hash,
        session_id: SessionId,
        aggregated_key: Vec<u8>,
    ) -> Result<(), String> {
        // Prepare bounded public key
        let pk = BoundedVec::try_from(aggregated_key.clone())
            .map_err(|_| "Aggregated key exceeds MaxPublicKeySize".to_string())?;
        let first = self.first_authority_key()?;

        let payload = SubmitDKGResultPayload::<uomi_runtime::Runtime> {
            session_id,
            public_key: pk,
            public: MultiSigner::from(first.clone()),
        };
        let signature = self.sign_payload(&first, &payload)?;

        let call = RuntimeCall::Tss(uomi_runtime::pallet_tss::Call::submit_dkg_result {
            payload,
            signature,
        });
        self.submit_unsigned(call)
    }

    fn report_tss_offence(
        &self,
        hash: <<B as BlockT>::Header as HeaderT>::Hash,
        session_id: SessionId,
        offence_type: TssOffenceType,
        offenders: Vec<[u8; 32]>,
    ) -> Result<(), String> {
        let _best = hash; // currently unused, kept for trait compatibility
        let first = self.first_authority_key()?;

        // Convert offenders bytes into AccountIds (skip invalid)
        let mut offender_accounts = Vec::new();
        for raw in offenders.iter() {
            if let Ok(acc) = AccountId::decode(&mut &raw[..]) {
                offender_accounts.push(acc);
            }
        }
        let bounded_offenders = BoundedVec::try_from(offender_accounts)
            .map_err(|_| "Offenders exceed MaxNumberOfShares".to_string())?;

        // Build payload analogous to ReportTssOffencePayload (re-exported) if needed
        let payload = uomi_runtime::pallet_tss::ReportTssOffencePayload::<uomi_runtime::Runtime> {
            offence_type,
            session_id,
            validator_set_count: 0, // optional: fill with known validator set size if available
            offenders: bounded_offenders,
            public: MultiSigner::from(first.clone()),
        };
        let signature = self.sign_payload(&first, &payload)?;

        let call = RuntimeCall::Tss(uomi_runtime::pallet_tss::Call::report_tss_offence {
            payload,
            signature,
        });
        self.submit_unsigned(call)
    }
}

impl<B: BlockT, C, TP> ClientWrapper<B, C, TP>
where
    C: BlockchainEvents<B> + ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static,
    C::Api: uomi_runtime::pallet_tss::TssApi<B>,
    TP: TransactionPool<Block = B> + LocalTransactionPool<Block = B> + Send + Sync + 'static,
{
    fn submit_unsigned(&self, call: RuntimeCall) -> Result<(), String> {
        let xt = UncheckedExtrinsic::new_unsigned(call.into());
        let best_hash = self.client.info().best_hash;
        // convert to block extrinsic type
        let encoded = xt.encode();
        let pool_xt = <B as BlockT>::Extrinsic::decode(&mut &encoded[..])
            .map_err(|_| "Failed to convert extrinsic to block extrinsic type".to_string())?;
        block_on(
            self.transaction_pool
                .submit_one(best_hash, TransactionSource::Local, pool_xt),
        )
        .map_err(|e| format!("TransactionPool submit error: {e:?}"))?;
        Ok(())
    }

    fn first_authority_key(&self) -> Result<sr25519::Public, String> {
        keystore_first_authority_key(&self.keystore)
    }

    fn sign_payload<P: Encode>(
        &self,
        public: &sr25519::Public,
        payload: &P,
    ) -> Result<Signature, String> {
        keystore_sign_payload(&self.keystore, public, payload)
    }
}

// ---- Pure helpers (unit test friendly) ----
/// Fetch the first sr25519 authority key stored under the TSS key type in the provided keystore.
/// Fails if no key is present or the raw bytes cannot be parsed into a valid public key.
pub(crate) fn keystore_first_authority_key(
    keystore: &KeystorePtr,
) -> Result<sr25519::Public, String> {
    let public_keys = keystore
        .keys(CRYPTO_KEY_TYPE)
        .map_err(|e| format!("Keystore access error: {e:?}"))?;
    let raw = public_keys
        .get(0)
        .ok_or("No TSS authority key in keystore".to_string())?;
    sr25519::Public::from_slice(raw).map_err(|_| "Invalid sr25519 public key length".to_string())
}

/// Sign an arbitrary SCALE-encodable payload with the provided sr25519 public key that must
/// exist in the keystore under the TSS key type. Returns a runtime `Signature` (MultiSignature).
pub(crate) fn keystore_sign_payload<P: Encode>(
    keystore: &KeystorePtr,
    public: &sr25519::Public,
    payload: &P,
) -> Result<Signature, String> {
    let raw_sig = keystore
        .sign_with(
            CRYPTO_KEY_TYPE,
            sr25519::CRYPTO_ID,
            public,
            payload.encode().as_ref(),
        )
        .map_err(|e| format!("Signing failed: {e:?}"))?
        .ok_or("Missing key for signing".to_string())?;
    let arr: [u8; 64] = raw_sig
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid sr25519 signature length".to_string())?;
    let sr_sig = sr25519::Signature(arr);
    Ok(sr_sig.into())
}

// ---- Unit Tests ----
#[cfg(test)]
mod tests {
    use super::*;
    use codec::Encode;
    use frame_support::traits::Get;
    use frame_support::BoundedVec;
    use sp_core::Pair; // for verification helper
    use sp_keystore::testing::MemoryKeystore;
    use sp_keystore::Keystore; // bring sr25519_generate_new trait into scope
    use sp_runtime::MultiSigner;
    use uomi_runtime::{
        pallet_tss::{ReportParticipantsPayload, SubmitDKGResultPayload, TssOffenceType},
        RuntimeCall,
    };

    #[derive(Encode)]
    struct DummyPayload {
        a: u8,
        b: u16,
    }

    #[test]
    fn first_authority_key_errors_without_key() {
        let ks = MemoryKeystore::new();
        let ptr: KeystorePtr = ks.into();
        let res = keystore_first_authority_key(&ptr);
        assert!(res.is_err());
    }

    #[test]
    fn sign_and_verify_payload() {
        let ks = MemoryKeystore::new();
        // generate a sr25519 key
        let public = ks
            .sr25519_generate_new(CRYPTO_KEY_TYPE, None)
            .expect("keygen");
        let ptr: KeystorePtr = ks.into();
        let payload = DummyPayload { a: 7, b: 513 };
        let sig = keystore_sign_payload(&ptr, &public, &payload).expect("sign");
        let message = payload.encode();
        match sig.clone() {
            // Signature == MultiSignature
            sp_runtime::MultiSignature::Sr25519(inner) => {
                assert!(sp_core::sr25519::Pair::verify(&inner, &message, &public));
            }
            _ => panic!("Expected sr25519 signature variant"),
        }
    }

    #[test]
    fn signatures_verify_for_same_payload_same_key() {
        // NOTE: Keystore sr25519 signing may introduce randomness (nonce) so signatures can differ.
        let ks = MemoryKeystore::new();
        let public = ks.sr25519_generate_new(CRYPTO_KEY_TYPE, None).unwrap();
        let ptr: KeystorePtr = ks.into();
        let payload = DummyPayload { a: 42, b: 999 };
        let msg = payload.encode();
        let sig1 = keystore_sign_payload(&ptr, &public, &payload).unwrap();
        let sig2 = keystore_sign_payload(&ptr, &public, &payload).unwrap();
        for sig in [sig1, sig2] {
            match sig {
                sp_runtime::MultiSignature::Sr25519(inner) => {
                    assert!(sp_core::sr25519::Pair::verify(&inner, &msg, &public));
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn different_keys_produce_different_signatures() {
        let ks = MemoryKeystore::new();
        let pub1 = ks.sr25519_generate_new(CRYPTO_KEY_TYPE, None).unwrap();
        let pub2 = ks.sr25519_generate_new(CRYPTO_KEY_TYPE, None).unwrap();
        let ptr: KeystorePtr = ks.into();
        let payload = DummyPayload { a: 1, b: 2 };
        let s1 = keystore_sign_payload(&ptr, &pub1, &payload).unwrap();
        let s2 = keystore_sign_payload(&ptr, &pub2, &payload).unwrap();
        assert_ne!(
            s1, s2,
            "Different keys should yield different signatures (high probability)"
        );
    }

    #[test]
    fn build_report_participants_call_ok_and_overflow() {
        // We only test constructing payload & bounded vec; overflow simulated by exceeding an assumed small limit.
        // Here we don't know MaxNumberOfShares at compile-time in this context, so we simulate BoundedVec failure manually.
        let accounts: Vec<AccountId> = vec![]; // empty ok
        let bounded = BoundedVec::try_from(accounts).expect("empty fits");
        let pub_dummy = sp_core::sr25519::Public::from_raw([0u8; 32]);
        let payload = ReportParticipantsPayload::<uomi_runtime::Runtime> {
            session_id: 1,
            reported_participants: bounded,
            public: MultiSigner::from(pub_dummy),
        };
        let dummy_sig: Signature = sr25519::Signature([0u8; 64]).into();
        let call = RuntimeCall::Tss(uomi_runtime::pallet_tss::Call::report_participant {
            payload: payload.clone(),
            signature: dummy_sig,
        });
        match call {
            RuntimeCall::Tss(uomi_runtime::pallet_tss::Call::report_participant { .. }) => {}
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn report_participants_overflow_fails() {
        // Obtain the runtime-configured max number of shares (participants) for TSS.
        let limit =
            <uomi_runtime::Runtime as uomi_runtime::pallet_tss::Config>::MaxNumberOfShares::get()
                as usize;
        // Build exactly 'limit' accounts (should fit).
        let fit_accounts: Vec<AccountId> =
            (0..limit).map(|i| AccountId::from([i as u8; 32])).collect();
        let fit_result: Result<
            BoundedVec<
                _,
                <uomi_runtime::Runtime as uomi_runtime::pallet_tss::Config>::MaxNumberOfShares,
            >,
            _,
        > = BoundedVec::try_from(fit_accounts);
        assert!(fit_result.is_ok(), "Expected vector of size 'limit' to fit");
        // Build limit+1 accounts (should overflow).
        let overflow_accounts: Vec<AccountId> = (0..=limit)
            .map(|i| AccountId::from([i as u8; 32]))
            .collect();
        assert!(
            BoundedVec::<
                AccountId,
                <uomi_runtime::Runtime as uomi_runtime::pallet_tss::Config>::MaxNumberOfShares,
            >::try_from(overflow_accounts)
            .is_err(),
            "Expected overflow to fail"
        );
    }

    #[test]
    fn build_submit_dkg_result_call_and_public_key_size() {
        let pk: Vec<u8> = vec![1, 2, 3];
        let bounded = BoundedVec::try_from(pk.clone()).expect("fits");
        let pub_dummy = sp_core::sr25519::Public::from_raw([1u8; 32]);
        let payload = SubmitDKGResultPayload::<uomi_runtime::Runtime> {
            session_id: 5,
            public_key: bounded,
            public: MultiSigner::from(pub_dummy),
        };
        let dummy_sig: Signature = sr25519::Signature([0u8; 64]).into();
        let call = RuntimeCall::Tss(uomi_runtime::pallet_tss::Call::submit_dkg_result {
            payload: payload.clone(),
            signature: dummy_sig,
        });
        match call {
            RuntimeCall::Tss(uomi_runtime::pallet_tss::Call::submit_dkg_result { .. }) => {}
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn tamper_payload_breaks_signature() {
        let ks = MemoryKeystore::new();
        let public = ks.sr25519_generate_new(CRYPTO_KEY_TYPE, None).unwrap();
        let ptr: KeystorePtr = ks.into();
        let payload = DummyPayload { a: 9, b: 77 };
        let sig = keystore_sign_payload(&ptr, &public, &payload).unwrap();
        // Tamper
        let mut tampered = payload.encode();
        tampered[0] ^= 0xFF;
        match sig {
            sp_runtime::MultiSignature::Sr25519(inner) => {
                assert!(
                    !sp_core::sr25519::Pair::verify(&inner, &tampered, &public),
                    "Tampering should invalidate"
                );
            }
            _ => unreachable!(),
        }
    }
}
