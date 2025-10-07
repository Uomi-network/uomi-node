#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod tests;

#[cfg(test)]
mod mock;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod consts;
pub mod types;
mod payloads;
mod offchain;
mod opoc;
mod aimodelscalc;
pub mod ipfs;
pub mod crypto;
pub mod migrations;

pub use pallet::*; // Re-export pallet items so that they can be accessed from the crate namespace.
pub mod weights;
pub use weights::*;

use frame_support::pallet_prelude::DispatchClass;
use frame_support::weights::Weight;
use sp_runtime::Perbill;
use sp_staking::offence::{Offence, ReportOffence};
use sp_staking::{SessionIndex, EraIndex}; // public alias
use codec::{Decode, Encode};
use frame_support::{
    BoundedVec,
    Blake2_128Concat,
    Parameter,
    ensure,
    inherent::{InherentData, InherentIdentifier, IsFatalError, ProvideInherent},
    pallet_prelude::{
        DispatchError, DispatchResultWithPostInfo, Hooks, InvalidTransaction, IsType, 
        MaxEncodedLen, Member, RuntimeDebug, StorageDoubleMap, StorageMap, 
        TransactionPriority, TransactionSource, TransactionValidity, ValidTransaction, 
        ValidateUnsigned, ValueQuery, 
    },
    parameter_types,
    storage::types::StorageValue,
    traits::{Randomness, Get},
};
use frame_support::pallet_prelude::OptionQuery;
use frame_system::{
    ensure_none, ensure_signed, ensure_root, offchain::{AppCrypto, CreateSignedTransaction, SignedPayload, Signer}, pallet_prelude::{BlockNumberFor, OriginFor}
};
use pallet_ipfs::{
    self,
    MinExpireDuration,
    types::{Cid, ExpirationBlockNumber, UsableFromBlockNumber},
};
use pallet_session::{self as session};
use pallet_authorship as authorship;
use sp_core::{H160, U256};
use sp_runtime::{
    traits::{IdentifyAccount, Convert, SaturatedConversion},
    DispatchResult,
};
use sp_std::{
    collections::btree_map::BTreeMap,
    marker::PhantomData,
    vec,
    vec::Vec,
};
use types::{Address, AiModelKey, BlockNumber, Data, NftId, RequestId, Version};

use crate::ipfs::IpfsInterface;

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo)]
pub struct EmptyInherent; 

// Prima delle implementazioni del pallet, aggiungi:
#[derive(Encode)]
#[cfg_attr(feature = "std", derive(Debug, Decode))]
pub enum InherentError {
    // Definisci qui i tuoi errori specifici
    InvalidInherentValue,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo, MaxEncodedLen, Default, Copy)]
pub enum OpocLevel {
    #[default] Level0,
    Level1,
    Level2
}

// Implementa IsFatalError per il tuo enum
impl IsFatalError for InherentError {
    fn is_fatal_error(&self) -> bool {
        match self {
            InherentError::InvalidInherentValue => true,
        }
    }
}

// PALLET DECLARATION

// All pallet logic is defined in its own module and must be annotated by the `pallet` attribute.
#[frame_support::pallet]
pub mod pallet {
    use super::*;

    // Here are defined the constants and types that will be used by the pallet.
    parameter_types! {
        pub const MaxDataSize: u32 = 1024 * 1024; // bytes
        pub const BlockTime: u64 = 3; // seconds
    }
    
    // Pallet
    #[pallet::pallet]
    #[pallet::storage_version(migrations::STORAGE_VERSION)]
    pub struct Pallet<T>(PhantomData<T>);

    // Config
    #[pallet::config]
    pub trait Config: frame_system::Config
        + CreateSignedTransaction<Call<Self>>
        + session::Config<ValidatorId = <Self as frame_system::Config>::AccountId>
        + pallet_session::historical::Config
        + pallet_offences::Config
        + authorship::Config
        + pallet_ipfs::Config {
        type UomiAuthorityId: AppCrypto<Self::Public, Self::Signature>;
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Randomness: Randomness<Option<<Self as frame_system::Config>::Hash>, BlockNumberFor<Self>>;
        type IpfsPallet: ipfs::IpfsInterface<Self>;
        type MaxOffchainConcurrent: Get<u32>; // NOTE: This config is not used anymore, but kept for retro-compatibility.
        type InherentDataType: Default + Encode + Decode + Clone + Parameter + Member + MaxEncodedLen;
        type OffenceReporter: ReportOffence<
            <Self as frame_system::Config>::AccountId,
            pallet_session::historical::IdentificationTuple<Self>,
            EngineReportedOffence<Self>
        >;
    }

    // Events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        RequestAccepted {
            request_id: RequestId, // The request Id.
            address: Address, // The address of the request.
            nft_id: NftId, // The NFT ID of the request.
        },
        RequestCompleted {
            request_id: RequestId, // The request Id.
            output_data: Data, // The output data of the request.
            total_executions: u32, // The total executions of the request.
            total_consensus: u32, // The total consensus of the request.
        },
        OpocBlacklistAdd {
            account_id: T::AccountId, // The account ID of the validator.
            nft_id: NftId, // The NFT ID.
        },
        OpocBlacklistRemove {
            account_id: T::AccountId, // The account ID of the validator.
            nft_id: NftId, // The NFT ID.
        },
        OpocAssignmentAdd {
            request_id: RequestId, // The request ID.
            account_id: T::AccountId, // The account ID of the validator.
            expiration_block_number: BlockNumber, // The expiration block number.
        },
        OpocAssignmentRemove {
            request_id: RequestId, // The request ID.
            account_id: T::AccountId, // The account ID of the validator.
        },
        NodeOutputReceived {
            request_id: RequestId, // The request ID.
            account_id: T::AccountId, // The account ID of the validator.
            output_data: Data, // The output data of the request.
        },
        NodeVersionReceived {
            account_id: T::AccountId, // The account ID of the validator.
            version: Version, // The version of the node.
        },
        NodeOpocL0InferenceReceived {
            request_id: RequestId, // The request ID.
            account_id: T::AccountId, // The account ID of the validator.
            inference_index: u32, // The inference index.
            inference_proof: Data, // The inference proof.
        },
        // --- Offence reporting (structure only, no logic yet) ---
        EngineOffenceReported {
            offence_type: EngineOffenceType, // Type of offence
            request_id: RequestId,            // Request id context (instead of session id)
            offenders_count: u32,             // Number of offenders included
        },
        EngineValidatorSlashed {
            offender: T::AccountId,   // Offender account id
            offence_type: EngineOffenceType, // Offence type
            request_id: RequestId,    // Request id context
        },
        NodesWorksAdd {
            account_id: T::AccountId, // The account ID of the validator.
            request_id: RequestId, // The request ID.
        },// AGGIUNTO NUOVO
        NodesWorksRemove {
            account_id: T::AccountId, // The account ID of the validator.
            request_id: RequestId, // The request ID.
        },// AGGIUNTO NUOVO
        OpocTimeoutsAdd {
            request_id: RequestId, // The request ID.
            account_id: T::AccountId, // The account ID of the validator.
        },// AGGIUNTO NUOVO
        OpocTimeoutsRemove {
            request_id: RequestId, // The request ID.
            account_id: T::AccountId, // The account ID of the validator.
        },// AGGIUNTO NUOVO
        OpocErrorsAdd {
            request_id: RequestId, // The request ID.
            account_id: T::AccountId, // The account ID of the validator.
        }, // AGGIUNTO NUOVO
        OpocErrorsRemove {
            request_id: RequestId, // The request ID.
            account_id: T::AccountId, // The account ID of the validator.
        }, // AGGIUNTO NUOVO
    }

    // Errors
    #[pallet::error]
    pub enum Error<T> {
        SomethingWentWrong,
        InvalidAddress,
        InvalidCid,
    TooManyOffenders,
    OffenceAlreadyPending,
    OffenceNoValidOffenders,
    }

    // ------------------------------------------------------------
    // Offence reporting (structure only)
    // ------------------------------------------------------------
    // NOTE: This mirrors the TSS pallet structure but uses `RequestId` instead of `SessionId`.
    // No execution / processing logic is added yet – this is a scaffolding for future integration.

    // (No staking offence integration yet; keep lean dependencies)

    // Maximum offenders retained per reported engine offence (can be adjusted later).
    parameter_types! { pub const MaxEngineOffenders: u32 = 128; }
    // Max automatic timeout scans per block.
    // Max engine requests scanned per block for majority-output disagreement.
    parameter_types! { pub const MaxEngineRequestConsensusScans: u32 = 25; }

    #[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo, MaxEncodedLen)]
    #[repr(u8)]
    pub enum EngineOffenceType {
        /// Validator failed to provide required output within the allowed time window
        OutputTimeout = 0,
        /// Submitted output deemed invalid / inconsistent with consensus
        InvalidOutput = 1,
        /// Repeated failures or malicious behavior across requests
        RepeatedMisbehavior = 2,
    }

    #[derive(RuntimeDebug, Clone)]
    pub struct EngineReportedOffence<T: Config> {
        pub offence_type: EngineOffenceType,
        pub request_id: RequestId,
        pub session_index: SessionIndex,
        pub validator_set_count: u32,
        pub offenders: Vec<pallet_session::historical::IdentificationTuple<T>>,
    }

    impl<T: Config> Offence<pallet_session::historical::IdentificationTuple<T>> for EngineReportedOffence<T>
    where
        T: pallet_session::historical::Config,
        T: session::Config<ValidatorId = <T as frame_system::Config>::AccountId>,
    {
        const ID: [u8; 16] = *b"engine:offence__";
        type TimeSlot = RequestId;
        fn offenders(&self) -> Vec<pallet_session::historical::IdentificationTuple<T>> { self.offenders.clone() }
    fn session_index(&self) -> SessionIndex { self.session_index }
        fn validator_set_count(&self) -> u32 { self.validator_set_count }
        fn time_slot(&self) -> Self::TimeSlot { self.request_id }
        fn slash_fraction(&self, _offenders_count: u32) -> Perbill {
            match self.offence_type {
                EngineOffenceType::OutputTimeout => Perbill::from_percent(1),
                EngineOffenceType::InvalidOutput => Perbill::from_percent(2),
                EngineOffenceType::RepeatedMisbehavior => Perbill::from_percent(5),
            }
        }
    }

    /// Pending engine offences keyed by request id. (type, reporter, offenders)
    #[pallet::storage]
    #[pallet::getter(fn pending_engine_offences)]
    pub type PendingEngineOffences<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        RequestId,
        (EngineOffenceType, T::AccountId, BoundedVec<T::AccountId, MaxEngineOffenders>),
        OptionQuery,
    >;

    /// Prevent repeated slashing for the same (request_id, offence_type, offender)
    #[pallet::storage]
    pub type ProcessedEngineOffenderFlags<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat, RequestId,
        Blake2_128Concat, (T::AccountId, u8), // (offender, offence_type encoded)
        (),
        OptionQuery
    >;

    // Limit how many pending offences we process per block to bound weight.
    parameter_types! { pub const MaxEngineOffencesPerBlock: u32 = 10; }

    // InherentDidUpdate storage is used to store the execution of the inherent function.
	#[pallet::storage]
	pub(super) type InherentDidUpdate<T: Config> = StorageValue<
        _,
        bool,
        ValueQuery
    >; // TODO: Verificare se il (super) serve veramente, se funziona senza, toglierlo

	// NodesOutputs storage is used to store the outputs of the requests received by the run_request function.
	#[pallet::storage]
	pub type NodesOutputs<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		RequestId, // request_id
		Blake2_128Concat,
		T::AccountId, // account_id
		Data, // output_data
		ValueQuery
	>;

    // NodesWorks storage is used to store the number of works that have every validator
	#[pallet::storage]
	pub type NodesWorks<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId, // account_id
        Blake2_128Concat,
		RequestId, // request_id
		bool, // status of work
		ValueQuery
	>;

    // NodesVersions storage is used to store the versions of the nodes.
    #[pallet::storage]
    pub type NodesVersions<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId, // account_id
        Version, // version
        ValueQuery
    >;

    // NodesOpocL0Inferences storage is used to store the inferences executed by the opoc at level 0.
	#[pallet::storage]
	pub type NodesOpocL0Inferences<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        RequestId, // request_id
        Blake2_128Concat,
        T::AccountId, // account_id
        (
            u32, // inference_index
            Data, // inference_proof
        ),
        ValueQuery
	>;

    // Inputs storage is used to store the inputs of the requests received by the run_request function.
	#[pallet::storage]
	pub type Inputs<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        RequestId, // request_id
        (
            BlockNumber, // block_number
            H160, // address
            NftId, // nft_id
            U256, // nft_required_consensus
            U256, // nft_execution_max_time
            Cid, // nft_file_cid
            Data, // input_data
            Cid, // input_file_cid
        ),
        ValueQuery
	>;

    // Outputs storage is used to store the outputs of the requests received by the run_request function.
    // Added nft_id to securely link the output to the agent without relying on user-provided payload data.
    #[pallet::storage]
    pub type Outputs<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        RequestId, // request_id
        (
            Data, // output_data
            u32, // total executions
            u32, // total consensus
            U256, // nft_id (agent id)
        ),
        ValueQuery
    >;

	// OpocBlacklist storage is used to store the blacklist of validators
	#[pallet::storage]
	pub type OpocBlacklist<T: Config> = StorageDoubleMap<
		_,
        Blake2_128Concat,
        NftId, // nft_id
		Blake2_128Concat,
		T::AccountId, // account_id
		bool, // is_blacklisted
		ValueQuery
	>;

	// OpocAssignment storage is used to store the executions of the requests received by the run_request function.
	#[pallet::storage]
	pub type OpocAssignment<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        RequestId, // request_id
        Blake2_128Concat,
        T::AccountId, // account_id
        (BlockNumber, OpocLevel), // expiration_block_number
        ValueQuery
	>;

    // OpocTimeouts storage is used to store the number of timeouts that have every validator
	#[pallet::storage]
	pub type OpocTimeouts<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        RequestId, // request_id
        Blake2_128Concat,
		T::AccountId, // account_id
		bool, // status of timeout
		ValueQuery
	>;

    // Track (era, validator) pairs already reset to avoid double subtraction of reward points
    #[pallet::storage]
    pub type ProcessedOpocTimeoutEraResets<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat, EraIndex,
        Blake2_128Concat, T::AccountId,
        (),
        OptionQuery
    >;

    // OpocErrors storage is used to store the number of errors that have every validator
    #[pallet::storage]
    pub type OpocErrors<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        RequestId, // request_id
        Blake2_128Concat,
        T::AccountId, // account_id
		bool, // status of error
		ValueQuery
	>;

    // AIModels storage is used to store the AI models and their versions.
    #[pallet::storage]
    pub type AIModels<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        AiModelKey,
        (
            Data, // local_name
            Data, // previous_local_name
            BlockNumber, // available_from_block_number
        ),
        ValueQuery
    >;

    // Hooks are used to execute code in response to certain events.
    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        
        #[cfg(feature = "try-runtime")]
        fn try_state(_n: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
            Ok(())
        }
        // The `offchain_worker` function is executed by the offchain worker in the runtime at the beginning of each block.
        #[cfg(feature = "std")]
        fn offchain_worker(_: BlockNumberFor<T>) {
            log::info!("UOMI-ENGINE: Offchain worker started");

            // Check if the current node is a validator, do nothing if it is not.
            let is_validator = sp_io::offchain::is_validator();
            if !is_validator { // Do nothing if the node is not a validator.
                log::info!("UOMI-ENGINE: Current node is not a validator, skipping offchain worker.");
                return;
            }

            // Find the account id of the current node.
            let signer = Signer::<T, T::UomiAuthorityId>::all_accounts();
            if !signer.can_sign() { // Do nothing if the signer cannot sign.
                log::info!("UOMI-ENGINE: No local account available, skipping offchain worker.");
                return;
            }
            let public_keys = sp_io::crypto::sr25519_public_keys(crypto::CRYPTO_KEY_TYPE);
            let public_key = match public_keys.get(0) {
                Some(public_key) => public_key,
                None => { // Do nothing if the public key is not found.
                    log::info!("UOMI-ENGINE: No public key found, skipping offchain worker.");
                    return;
                }
            };
            let account_id = T::AccountId::decode(&mut &public_key.encode()[..]).unwrap();

            // Run the offchain worker entry point.
            Self::offchain_run(&account_id).unwrap_or_else(|e| {
                log::error!("Error running offchain worker: {:?}", e);
            });
        }

		fn on_finalize(_: BlockNumberFor<T>) {
            let current_block_number = U256::from(0) + <frame_system::Pallet<T>>::block_number();

            match Self::opoc_run(current_block_number) {
                Ok(operations) => {
                    Self::opoc_store_operations(operations);
                },
                Err(error) => {
                    log::error!("Error running opoc_run: {:?}", error);
                },
            };

            match Self::aimodelscalc_run(current_block_number) {
                Ok(operations) => {
                    Self::aimodelscalc_store_operations(operations);
                },
                Err(error) => {
                    log::error!("Error running aimodelscalc_run: {:?}", error);
                },
            };

            // TEMPORARY MOD FOR TURING TESTNET: Every 1000 blocks we reset the OpocBlacklist storage to permit blacklisted validators to be selected again
            let divisor = U256::from(1000);
            if current_block_number % divisor == U256::zero() {
                log::info!("UOMI-ENGINE: Resetting OpocBlacklist storage");
                OpocBlacklist::<T>::remove_all(None);
            }

            // Reset validators' current era points at the end of each era to avoid overflow.
            Self::reset_validators_current_era_points_for_current_era().unwrap_or_else(|e| {
                log::error!("Error resetting validators' current era points: {:?}", e);
            });

            // Be sure that the InherentDidUpdate is set to true and reset it to false.
            // This is required to be sure that the inherent function is executed once in the block.
            assert!(InherentDidUpdate::<T>::take(), "UOMI-ENGINE: inherent must be updated once in the block");
		}

        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            Self::detect_invalid_output_offences();
            if let Err(e) = Self::process_pending_engine_offences() { log::error!("[ENGINE] Offence processing failed: {:?}", e); }
            Weight::from_parts(20_000,0)
        }
    }

    // The pallet's dispatchable functions that require unsigned payloads are defined here.
    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;
    
        fn validate_unsigned(source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::set_inherent_data { .. } => {
                    ValidTransaction::with_tag_prefix("UomiEnginePallet")
                        .priority(TransactionPriority::MAX)
                        .and_provides(consts::PALLET_INHERENT_IDENTIFIER)
                        .longevity(64_u64)
                        .propagate(true)
                        .build()
                },
                Call::store_nodes_outputs {  payload, signature } => {
                    if !Self::verify_signature(payload.public.clone(), payload, signature) {
                        return InvalidTransaction::BadProof.into();
                    }

                    ValidTransaction::with_tag_prefix("UomiEnginePallet")
                        .priority(TransactionPriority::MAX)
                        .and_provides(&call)
                        .longevity(64_u64)
                        .propagate(true)
                        .build()
                },
                Call::store_nodes_versions {  payload, signature  } => {

                    if !Self::verify_signature(payload.public.clone(), payload, signature) {
                        return InvalidTransaction::BadProof.into();
                    }

                    ValidTransaction::with_tag_prefix("UomiEnginePallet")
                        .priority(TransactionPriority::MAX)
                        .and_provides(&call)
                        .longevity(64_u64)
                        .propagate(true)
                        .build()
                },
                Call::store_nodes_opoc_l0_inferences { payload, signature } => {

                    if !Self::verify_signature(payload.public.clone(), payload, signature) {
                        return InvalidTransaction::BadProof.into();
                    }

                    ValidTransaction::with_tag_prefix("UomiEnginePallet")
                        .priority(TransactionPriority::MAX)
                        .and_provides(&call)
                        .longevity(64_u64)
                        .propagate(true)
                        .build()
                },
                _ => {
                    InvalidTransaction::Call.into()
                }
            }
        }
    }

    // Internal helper impl block (after hooks / unsigned validation)
    impl<T: Config> Pallet<T> {
        fn insert_pending_offence(
            request_id: RequestId,
            reporter: T::AccountId,
            offence_type: EngineOffenceType,
            offenders: Vec<T::AccountId>,
        ) -> DispatchResult {
            ensure!(!PendingEngineOffences::<T>::contains_key(&request_id), Error::<T>::OffenceAlreadyPending);
            let mut uniq: Vec<T::AccountId> = Vec::new();
            for a in offenders { if !uniq.contains(&a) { uniq.push(a); } }
            ensure!(!uniq.is_empty(), Error::<T>::OffenceNoValidOffenders);
            let bounded: BoundedVec<T::AccountId, MaxEngineOffenders> = uniq.clone().try_into().map_err(|_| Error::<T>::TooManyOffenders)?;
            PendingEngineOffences::<T>::insert(&request_id, (offence_type, reporter.clone(), bounded.clone()));


            // We delete all OpocErrors with request_id=request_id
            OpocErrors::<T>::remove_prefix(&request_id, None);


            Self::deposit_event(Event::EngineOffenceReported { offence_type, request_id, offenders_count: bounded.len() as u32 });
            Ok(())
        }

        // Detect invalid outputs using OpocErrors storage: any validator flagged with an error
        // (OpocErrors[rid][validator] == true) is considered an offender for InvalidOutput.
        // We scan distinct request_ids up to MaxEngineRequestConsensusScans per block.
        fn detect_invalid_output_offences() {
            use sp_std::collections::btree_set::BTreeSet;
            let mut processed: BTreeSet<RequestId> = BTreeSet::new();
            for (rid, _acc, flag) in OpocErrors::<T>::iter() {
                if !flag { continue; }
                if processed.len() as u32 >= MaxEngineRequestConsensusScans::get() { break; }
                if processed.contains(&rid) { continue; }
                processed.insert(rid);
                let offenders: Vec<T::AccountId> = OpocErrors::<T>::iter_prefix(rid)
                    .filter(|(_, has_err)| *has_err)
                    .map(|(acc, _)| acc)
                    .collect();
                if offenders.is_empty() { continue; }

                // Check if the request was completed, aka it's in Outputs
                if !Outputs::<T>::contains_key(&rid) {
                    // request was not completed yet, this might be not an error yet
                    continue;
                }

                // Reporter: current block author if available and not among offenders, otherwise first non-offender with output, else first offender.
                let block_author_opt = <authorship::Pallet<T>>::author();
                let reporter = block_author_opt
                    .filter(|a| !offenders.contains(a))
                    .or_else(||
                        NodesOutputs::<T>::iter_prefix(rid)
                            .find(|(acc, _)| !offenders.contains(acc))
                            .map(|(acc, _)| acc)
                    )
                    .or_else(|| offenders.first().cloned());
                if let Some(rep) = reporter { let _ = Self::insert_pending_offence(rid, rep, EngineOffenceType::InvalidOutput, offenders); }
            }
        }

        pub fn process_pending_engine_offences() -> DispatchResult {
            let mut to_process: Vec<RequestId> = Vec::new();
            for (rid, _) in PendingEngineOffences::<T>::iter().take(MaxEngineOffencesPerBlock::get() as usize) { to_process.push(rid); }
            for rid in to_process.into_iter() {
                if let Some((off_type, reporter, offenders)) = PendingEngineOffences::<T>::take(rid) {
                    let session_index = session::Pallet::<T>::current_index();
                    let mut tuples: Vec<pallet_session::historical::IdentificationTuple<T>> = Vec::new();
                    for acc in offenders.into_inner() {
                        let key = (acc.clone(), off_type as u8);
                        if ProcessedEngineOffenderFlags::<T>::contains_key(rid, key.clone()) { continue; }
                        if let Some(full) = <T as pallet_session::historical::Config>::FullIdentificationOf::convert(acc.clone()) {
                            tuples.push((acc.clone(), full));
                            ProcessedEngineOffenderFlags::<T>::insert(rid, key, ());
                        }
                    }
                    if tuples.is_empty() { continue; }
                    let validator_set_count = pallet_session::Pallet::<T>::validators().len() as u32;
                    let offence = EngineReportedOffence::<T> {
                        offence_type: off_type,
                        request_id: rid,
                        session_index,
                        validator_set_count,
                        offenders: tuples.clone(),
                    };
                    // if let Err(e) = T::OffenceReporter::report_offence(vec![reporter.clone()], offence) {
                    //     log::error!("[ENGINE] Report offence failed: {:?}", e);
                    // } else {
                 
                        log::info!("[ENGINE] Reported offence: {:?}, request_id: {:?}, reporter: {:?}, offenders: {:?}", off_type, rid, reporter, tuples.iter().map(|(acc, _)| acc).collect::<Vec<_>>());
                        for (acc, _) in tuples.into_iter() { Self::deposit_event(Event::EngineValidatorSlashed { offender: acc, offence_type: off_type, request_id: rid }); }
                
                }
            }
            Ok(())
        }
    }

    // Calls are the dispatchable functions that can be called by users and offchain workers.
    #[pallet::call]
    impl<T: Config> Pallet<T> {

        // NOTE: Set inherent data is not used anymore, but kept for reference.
		#[pallet::call_index(0)]
		#[pallet::weight((500_000, DispatchClass::Mandatory))]
		pub fn set_inherent_data(
			origin: OriginFor<T>,
            opoc_operations: (
                BTreeMap<T::AccountId, bool>,
                BTreeMap<(RequestId, T::AccountId), (BlockNumber, OpocLevel)>, 
                BTreeMap<T::AccountId, BTreeMap<RequestId, bool>>, // nodes_works_operations
                BTreeMap<RequestId, BTreeMap<T::AccountId, bool>>, // opoc_timeouts_operations
                BTreeMap<RequestId, BTreeMap<T::AccountId, bool>>, // opoc_errors_operations
                BTreeMap<RequestId, (Data, u32, u32, U256)>
            ),
            aimodelscalc_operations: BTreeMap<AiModelKey, (Data, Data, BlockNumber)>,
		) -> DispatchResultWithPostInfo {
			ensure_none(origin)?;
            assert!(!InherentDidUpdate::<T>::exists(), "Inherent data must be updated only once in the block");

			InherentDidUpdate::<T>::set(true);
			Ok(().into())
		}
        
        #[pallet::call_index(1)]
        #[pallet::weight(0)]
        pub fn store_nodes_outputs(
            origin: OriginFor<T>,
            payload: payloads::PayloadNodesOutputs<T::Public>,
			_signature: T::Signature
        ) -> DispatchResult {
            ensure_none(origin)?;

            let payloads::PayloadNodesOutputs { request_id, output_data, public } = payload;

            let public_account_id = public.into_account();

            if !Self::address_is_active_validator(&public_account_id) {
                return Err("Only validators can call this function".into());
            }

            let output_already_exists = |request_id: U256, account_id: &T::AccountId| -> bool {
                NodesOutputs::<T>::contains_key(request_id, account_id)
            };
            if output_already_exists(request_id, &public_account_id) {
                return Err("Request ID already exists".into());
            }

            NodesOutputs::<T>::insert(request_id, public_account_id.clone(), output_data.clone());

            Self::deposit_event(Event::NodeOutputReceived { request_id, account_id: public_account_id, output_data });

            Ok(())
        }
        
        #[pallet::call_index(2)]
        #[pallet::weight(0)]
        pub fn store_nodes_versions(
            origin: OriginFor<T>, 
            payload: payloads::PayloadNodesVersions<T::Public>,
            _signature: T::Signature
        ) -> DispatchResult {
            ensure_none(origin)?;
            let payloads::PayloadNodesVersions { public, version } = payload;
            let public_account_id = public.into_account();

            if !Self::address_is_active_validator(&public_account_id) {
                return Err("Only validators can call this function".into());
            }

            let current_stored_version = NodesVersions::<T>::get(&public_account_id);
            if current_stored_version == version {
                return Err("Version already stored".into());
            }

            NodesVersions::<T>::set(public_account_id.clone(), version);

            Self::deposit_event(Event::NodeVersionReceived { account_id: public_account_id, version });

            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(0)]
        pub fn temporary_cleanup_inputs(origin: OriginFor<T>) -> DispatchResult {
            log::info!("UOMI-ENGINE: Cleaning up inputs");
            let _ = ensure_signed(origin)?;
            
            // remove all data on Inputs storage
            // let inputs = Inputs::<T>::iter().collect::<Vec<_>>();
            // for (request_id, _) in inputs {
            //    Inputs::<T>::remove(request_id);
            // }

            Ok(())
        }
       

        #[pallet::call_index(4)]
        #[pallet::weight(0)]
        pub fn store_nodes_opoc_l0_inferences(
            origin: OriginFor<T>, 
            payload: payloads::PayloadNodesOpocL0Inferences<T::Public>,
            _signature: T::Signature
        ) -> DispatchResult {
            ensure_none(origin)?;
            let payloads::PayloadNodesOpocL0Inferences { public, request_id, inference_index, inference_proof } = payload;
            let public_account_id = public.into_account();

            if !Self::address_is_active_validator(&public_account_id) {
                return Err("Only validators can call this function".into());
            }

            // check if another inference with the same request_id, account_id and inference_index already exists
            let inference_already_exists = |request_id: U256, account_id: &T::AccountId, inference_index: u32| -> bool {
                NodesOpocL0Inferences::<T>::contains_key(request_id, account_id) && NodesOpocL0Inferences::<T>::get(request_id, account_id).0 == inference_index
            };
            if inference_already_exists(request_id, &public_account_id, inference_index) {
                return Err("Inference already exists".into());
            }

            NodesOpocL0Inferences::<T>::insert(request_id, public_account_id.clone(), (inference_index, inference_proof.clone()));

            Self::deposit_event(Event::NodeOpocL0InferenceReceived { request_id, account_id: public_account_id, inference_index, inference_proof });

            Ok(())
        }

        #[pallet::call_index(240)]
        #[pallet::weight(10_000)]
        pub fn report_engine_offence(
            origin: OriginFor<T>,
            request_id: RequestId,
            offence_type_raw: u8,
            offenders: Vec<T::AccountId>,
        ) -> DispatchResult {
            let reporter = ensure_signed(origin)?;
            let offence_type = match offence_type_raw { 0 => EngineOffenceType::OutputTimeout, 1 => EngineOffenceType::InvalidOutput, 2 => EngineOffenceType::RepeatedMisbehavior, _ => return Err(Error::<T>::SomethingWentWrong.into()) };
            Self::insert_pending_offence(request_id, reporter, offence_type, offenders)
        }

        #[pallet::call_index(5)]
        #[pallet::weight(0)]
        pub fn force_clear_all_opoc_blacklist(origin: OriginFor<T>) -> DispatchResult {
            log::info!("UOMI-ENGINE: Forcing clear of OpocBlacklist");
            let _ = ensure_root(origin)?;

            OpocBlacklist::<T>::remove_all(None);

            Ok(())
        }
    }

    // Inherent functions are used to execute code at the beginning of each block.
    // NOTE: Inherent are not used anymore, but the structure is kept for future use.
    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = InherentError;
        const INHERENT_IDENTIFIER: InherentIdentifier = consts::PALLET_INHERENT_IDENTIFIER;
    
        fn create_inherent(_data: &InherentData) -> Option<Self::Call> {
            Some(Call::set_inherent_data { 
                opoc_operations: (BTreeMap::new(), BTreeMap::new(), BTreeMap::new(), BTreeMap::new(), BTreeMap::new(), BTreeMap::new()),
                aimodelscalc_operations: BTreeMap::new(),
            })
        }
    
        fn check_inherent(call: &Self::Call, _data: &InherentData) -> Result<(), Self::Error> {
            Ok(())        
        }
        
        fn is_inherent(call: &Self::Call) -> bool {
            let is_inherent = matches!(call, Call::set_inherent_data { .. });
            is_inherent
        }
    }
}

// PALLET FUNCTIONS
//////////////////////////////////////////////////////////////////////////////////

impl<T: Config> Pallet<T> {

    // RUN REQUEST FUNCTION
    //////////////////////////////////////////////////////////////////////////////////

    // This function is used by the runtime to run a request on the UOMI Network.
    pub fn run_request(
        request_id: U256,
        address: H160,
        nft_id: U256,
        input_data: Vec<u8>,
        input_file_cid: Vec<u8>,
        min_validators: U256,
        min_blocks: U256,
    ) -> DispatchResult {
        // Be sure request_id is > 0
        ensure!(request_id > U256::zero(), "Request ID must be greater than 0.");
        // Be sure address is not zero
        ensure!(address != H160::zero(), "Address must not be zero.");
        // Be sure nft_id is > 0
        ensure!(nft_id > U256::zero(), "NFT ID must be greater than 0.");
        // Be sure request_id is not already in the Inputs storage
        ensure!(!Inputs::<T>::contains_key(request_id), "Request ID already exists.");

        // Get the current block number in U256 format
        let block_number: U256 = frame_system::Pallet::<T>::block_number().into();

        // Get input_data and input_file_cid in BoundedVec<u8, MaxDataSize> format
        let input_data: BoundedVec<u8, MaxDataSize> = input_data
            .clone()
            .try_into()
            .map_err(|_| "Input data too large.")?;
        let input_file_cid: Cid = input_file_cid
            .clone()
            .try_into()
            .map_err(|_| Error::<T>::InvalidCid)?;

        // Be sure to pin the input_file_cid if it is not empty
        if !input_file_cid.is_empty() {
            let account_id = Self::h160_to_account_id(address)?;
            let origin = frame_system::RawOrigin::Signed(account_id).into();
            T::IpfsPallet::pin_file(origin, input_file_cid.clone(), MinExpireDuration::get().into())?;
        }

        // Get the nft_file_cid from the nft_id
        let nft_file_cid;
        if cfg!(test) { // For testing purposes, we set the nft_file_cid to default
            nft_file_cid = Cid::default();
        } else {
            nft_file_cid = match T::IpfsPallet::get_agent_cid(nft_id) {
                Ok(cid) => cid,
                Err(error) => {
                    log::error!("UOMI-ENGINE: Failed to get agent from NFT ID on run_request. error: {:?}", error);
                    return Err("Failed to get agent from NFT ID.".into());
                },
            };

            // Be sure the nft_file_cid is valid and pinned by nodes
            let (nft_file_cid_expiration_block_number, nft_file_cid_usable_from_block_number) =
                match T::IpfsPallet::get_cid_status(&nft_file_cid) {
                    Ok((expiration_block_number, usable_from_block_number)) =>
                        (expiration_block_number, usable_from_block_number),
                    Err(error) => {
                        log::error!(
                            "UOMI-ENGINE: Failed to get status of nft file cid {:?}. error: {:?}",
                            nft_file_cid,
                            error
                        );
                        return Err("Failed to get status of nft file cid.".into());
                    }
                };
            
            let ipfs_min_expire_duration = U256::from(MinExpireDuration::get());
            let current_block = frame_system::Pallet::<T>::block_number().into();
            if
                nft_file_cid_expiration_block_number != ExpirationBlockNumber::zero() &&
                block_number + ipfs_min_expire_duration > nft_file_cid_expiration_block_number
            {
                return Err("NFT file cid expired before the minimum expiration duration.".into());
            }
            if nft_file_cid_usable_from_block_number == UsableFromBlockNumber::zero() {
                return Err("NFT file cid not usable yet.".into());
            }
            if nft_file_cid_usable_from_block_number > current_block {
                return Err("NFT file cid not usable yet.".into());
            }
        }
       
        // Get the minimum number of validators required for the request to be considered valid
        let nft_required_consensus = min_validators;
        let nft_execution_max_time = min_blocks;

        // Store the inputs in the Inputs storage
        Inputs::<T>::insert(request_id, (block_number, address, nft_id, nft_required_consensus, nft_execution_max_time, nft_file_cid, input_data, input_file_cid));

        // Emit the RequestAccepted event
        Self::deposit_event(Event::RequestAccepted { request_id, address, nft_id });

        Ok(())
    }

    // OTHER FUNCTIONS
    //////////////////////////////////////////////////////////////////////////////////
    
    // This function is used to check if an address is a validator.
    pub fn address_is_active_validator(account_id: &T::AccountId) -> bool {
        // TODO: For tests we return validators only from pallet_staking::Validators::<T>.
        // In the future we should fix tests to return validators from session::Validators::<T>.
        if cfg!(test) {
            return pallet_staking::Validators::<T>::contains_key(account_id);
        }

        let active_validators = pallet_session::Validators::<T>::get();
        let validator_id = T::ValidatorId::try_from(account_id.clone()).ok().unwrap();

        active_validators.contains(&validator_id)
    }

    // TODO: It should be better to load directly validators from session::Validators::<T> but we need to find a way to convert them to T::AccountId
    pub fn get_active_validators() -> Vec<T::AccountId> {
        // TODO: For tests we return validators only from pallet_staking::Validators::<T>.
        // In the future we should fix tests to return validators from session::Validators::<T>.
        if cfg!(test) {
            return pallet_staking::Validators::<T>::iter().map(|(account_id, _)| account_id).collect();
        }

        let validators: Vec<T::AccountId> = pallet_staking::Validators::<T>::iter().map(|(account_id, _)| account_id)
            .into_iter()
            .filter(|account_id| Self::address_is_active_validator(account_id))
            .collect();
    
        validators
    }

    // TODO: It should be better to load directly validators from session::Validators::<T> but we need to find a way to convert them to T::AccountId
    pub fn get_active_validators_count() -> u32 {
        let validators = Self::get_active_validators();
        validators.len() as u32
    }

    fn h160_to_account_id(address: H160) -> Result<T::AccountId, DispatchError> {
        let mut data = [0u8; 32];
        data[0..20].copy_from_slice(&address.as_bytes());
        T::AccountId::decode(&mut &data[..])
            .map_err(|_| DispatchError::Other("Failed to decode account"))
    }

    /// Verify a payload's signature
    pub fn verify_signature<SP>(
        public: T::Public, 
        payload: &SP, 
        signature: &T::Signature 
    )-> bool where 
    SP:SignedPayload<T>,
     {
        if Self::address_is_active_validator(&public.into_account()) {
            // Convert the public key to an account ID before verifying
            T::UomiAuthorityId::verify(&payload.encode(), payload.public(), signature.clone())
        } else {
            false
        }
    }
}


impl<T: Config> uomi_primitives::UomiEngineInterface<T> for Pallet<T> {
    fn clear_blacklist_for_nft(nft_id: U256) -> DispatchResult {
        OpocBlacklist::<T>::remove_prefix(nft_id, None);
        Ok(())
    }
}