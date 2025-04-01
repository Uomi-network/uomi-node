#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod tests;

#[cfg(test)]
mod mock;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

mod consts;
mod types;
mod payloads;
mod offchain;
mod opoc;
mod aimodelscalc;
pub mod ipfs;
pub mod crypto;

pub use pallet::*; // Re-export pallet items so that they can be accessed from the crate namespace.
pub mod weights;
pub use weights::*;

use frame_support::pallet_prelude::DispatchClass;
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
    traits::Randomness,
};
use frame_system::{
    ensure_none, ensure_signed, offchain::{AppCrypto, CreateSignedTransaction, SignedPayload, Signer}, pallet_prelude::{BlockNumberFor, OriginFor}
};
use pallet_ipfs::{
    self,
    MinExpireDuration,
    types::{Cid, ExpirationBlockNumber, UsableFromBlockNumber},
};
use pallet_session::{self as session};
use sp_core::{H160, U256};
use sp_runtime::{
    traits::IdentifyAccount,
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
    pub struct Pallet<T>(PhantomData<T>);

    // Config
	#[pallet::config]
	pub trait Config: frame_system::Config + CreateSignedTransaction<Call<Self>> + session::Config + pallet_ipfs::Config {
		type UomiAuthorityId: AppCrypto<Self::Public, Self::Signature>;
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type RandomnessOld: Randomness<<Self as frame_system::Config>::Hash, BlockNumberFor<Self>>; // For finney update. remove on turing
		type Randomness: Randomness<Option<<Self as frame_system::Config>::Hash>, BlockNumberFor<Self>>;
        type IpfsPallet: ipfs::IpfsInterface<Self>;
        type InherentDataType: Default + Encode + Decode + Clone + Parameter + Member + MaxEncodedLen;


        
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
        },
        OpocBlacklistRemove {
            account_id: T::AccountId, // The account ID of the validator.
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
    }

    // Errors
    #[pallet::error]
    pub enum Error<T> {
        SomethingWentWrong,
        InvalidAddress,
        InvalidCid,
    }

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

    // NodesTimeouts storage is used to store the number of timeouts that have every validator
	#[pallet::storage]
	pub type NodesTimeouts<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId, // account_id
        u32, // number_of_timeouts
        ValueQuery
	>;

    // NodesErrors storage is used to store the number of errors that have every validator
    #[pallet::storage]
    pub type NodesErrors<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId, // account_id
        u32, // number_of_errors
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
            NftId, // nft_id
            U256, // nft_required_consensus
            U256, // nft_execution_max_time
            Cid, // nft_file_cid
            Data, // input_data
            Cid, // input_file_cidx
        ),
        ValueQuery
	>;

	// Outputs storage is used to store the outputs of the requests received by the run_request function.
	#[pallet::storage]
	pub type Outputs<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		RequestId, // request_id
		(
			Data, // output_data
			u32, // total executions
			u32, // total conseusus
		),
		ValueQuery
	>;

	// OpocBlacklist storage is used to store the blacklist of validators
	#[pallet::storage]
	pub type OpocBlacklist<T: Config> = StorageMap<
		_,
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
        BlockNumber, // expiration_block_number
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
        // The `offchain_worker` function is executed by the offchain worker in the runtime at the beginning of each block.
        #[cfg(feature = "std")]
        fn offchain_worker(_: BlockNumberFor<T>) {
            // Check if the current node is a validator, do nothing if it is not.
            let is_validator = sp_io::offchain::is_validator();
            if !is_validator { // Do nothing if the node is not a validator.
                return;
            }

            // Find the account id of the current node.
            let signer = Signer::<T, T::UomiAuthorityId>::all_accounts();
            if !signer.can_sign() { // Do nothing if the signer cannot sign.
                return;
            }
            let public_keys = sp_io::crypto::sr25519_public_keys(crypto::CRYPTO_KEY_TYPE);
            let public_key = match public_keys.get(0) {
                Some(public_key) => public_key,
                None => { // Do nothing if the public key is not found.
                    return;
                }
            };
            let account_id = T::AccountId::decode(&mut &public_key.encode()[..]).unwrap();

            // Run the offchain worker entry point.
            Self::offchain_run(&account_id).unwrap_or_else(|e| {
                log::error!("Error running offchain worker: {:?}", e);
            });
        }

		fn on_finalize(_n: BlockNumberFor<T>) {
            // Be sure that the InherentDidUpdate is set to true and reset it to false.
            // This is required to be sure that the inherent function is executed once in the block.
            assert!(InherentDidUpdate::<T>::take(), "UOMI-ENGINE: inherent must be updated once in the block");
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

                    // Existing validation for store_nodes_outputs
                    if source == TransactionSource::External { // NOTE: This code is used to maintain the retro-compatibility with old blocks on finney network
                        return InvalidTransaction::BadSigner.into()
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

                    // Existing validation for store_nodes_versions
                    if source == TransactionSource::External { // NOTE: This code is used to maintain the retro-compatibility with old blocks on finney network
                        return InvalidTransaction::BadSigner.into()
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
                    
                    // Existing validation for store_nodes_versions
                    if source == TransactionSource::External { // NOTE: This code is used to maintain the retro-compatibility with old blocks on finney network
                        return InvalidTransaction::BadSigner.into()
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

    // Calls are the dispatchable functions that can be called by users and offchain workers.
    #[pallet::call]
    impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight((500_000, DispatchClass::Mandatory))]
		pub fn set_inherent_data(
			origin: OriginFor<T>,
			opoc_operations: (
                BTreeMap<T::AccountId, bool>, 
                BTreeMap<(RequestId, T::AccountId), BlockNumber>, 
                BTreeMap<T::AccountId, BTreeMap<RequestId, bool>>, 
                BTreeMap<T::AccountId, u32>, 
                BTreeMap<T::AccountId, u32>, 
                BTreeMap<RequestId, (Data, u32, u32)>
            ),
            aimodelscalc_operations: BTreeMap<AiModelKey, (Data, Data, BlockNumber)>,
		) -> DispatchResultWithPostInfo {
			ensure_none(origin)?;
            assert!(!InherentDidUpdate::<T>::exists(), "Inherent data must be updated only once in the block");
			
            Self::opoc_store_operations(opoc_operations)?;
            Self::aimodelscalc_store_operations(aimodelscalc_operations)?;

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
        pub fn temporary_cleanup_inputs(origin: OriginFor<T>) -> DispatchResult { // NOTE: This code is used to maintain the retro-compatibility with old blocks on finney network
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
        pub fn temporary_function(origin: OriginFor<T>) -> DispatchResult { // NOTE: This code is used to maintain the retro-compatibility with old blocks on finney network
            let _ = ensure_none(origin)?;
            Ok(())
        }

        #[pallet::call_index(5)]
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
    }

    // Inherent functions are used to execute code at the beginning of each block.
    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = InherentError;
        const INHERENT_IDENTIFIER: InherentIdentifier = consts::PALLET_INHERENT_IDENTIFIER;
    
        fn create_inherent(_data: &InherentData) -> Option<Self::Call> {
            let current_block_number = frame_system::Pallet::<T>::block_number().into();

            let opoc_operations = match Self::opoc_run(current_block_number) {
                Ok(operations) => {
                    operations
                },
                Err(error) => {
                    return None;
                },
            };

            let aimodelscalc_operations = match Self::aimodelscalc_run(current_block_number) {
                Ok(operations) => {
                    operations
                },
                Err(error) => {
                    return None;
                },
            };

            Some(Call::set_inherent_data { 
                opoc_operations,
                aimodelscalc_operations
            })
        }
    
        fn check_inherent(call: &Self::Call, _data: &InherentData) -> Result<(), Self::Error> {
            let current_block_number = frame_system::Pallet::<T>::block_number().into();
            let expected_block_number = current_block_number + 1;

            match call {
                Call::set_inherent_data { opoc_operations, aimodelscalc_operations } => {
                    // let expected_opoc_operations = match Self::opoc_run(expected_block_number) {
                    //     Ok(opoc_operations) => {
                    //         opoc_operations
                    //     },
                    //     Err(error) => {
                    //         log::info!("UOMI-ENGINE: Failed to run OPoC on check_inherent. error: {:?}", error);
                    //         return Err(InherentError::InvalidInherentValue);
                    //     },
                    // };
                    // let (opoc_blacklist_operations, opoc_assignment_operations, nodes_works_operations, nodes_timeouts_operations, outputs_operations, nodes_errors_operations) = opoc_operations;
                    // let (expected_opoc_blacklist_operations, expected_opoc_assignment_operations, expected_nodes_works_operations, expected_nodes_timeouts_operations, expected_outputs_operations, expected_nodes_errors_operations) = expected_opoc_operations;
                    
                    // if opoc_blacklist_operations != &expected_opoc_blacklist_operations {
                    //     log::info!("failed check opoc_blacklist_operations: {:?}", opoc_blacklist_operations);
                    //     log::info!("expected_opoc_blacklist_operations: {:?}", expected_opoc_blacklist_operations);
                    //     return Err(InherentError::InvalidInherentValue);
                    // }
                    // if opoc_assignment_operations != &expected_opoc_assignment_operations {
                    //     log::info!("failed check opoc_assignment_operations: {:?}", opoc_assignment_operations);
                    //     log::info!("expected_opoc_assignment_operations: {:?}", expected_opoc_assignment_operations);
                    //     return Err(InherentError::InvalidInherentValue);
                    // }
                    // if nodes_works_operations != &expected_nodes_works_operations {
                    //     log::info!("failed check nodes_works_operations: {:?}", nodes_works_operations);
                    //     log::info!("expected_nodes_works_operations: {:?}", expected_nodes_works_operations);
                    //     return Err(InherentError::InvalidInherentValue);
                    // }
                    // if nodes_timeouts_operations != &expected_nodes_timeouts_operations {
                    //     log::info!("failed check nodes_timeouts_operations: {:?}", nodes_timeouts_operations);
                    //     log::info!("expected_nodes_timeouts_operations: {:?}", expected_nodes_timeouts_operations);
                    //     return Err(InherentError::InvalidInherentValue);
                    // }
                    // if outputs_operations != &expected_outputs_operations {
                    //     log::info!("failed check outputs_operations: {:?}", outputs_operations);
                    //     log::info!("expected_outputs_operations: {:?}", expected_outputs_operations);
                    //     return Err(InherentError::InvalidInherentValue);
                    // }
                    // if nodes_errors_operations != &expected_nodes_errors_operations {
                    //     log::info!("failed check nodes_errors_operations: {:?}", nodes_errors_operations);
                    //     log::info!("expected_nodes_errors_operations: {:?}", expected_nodes_errors_operations);
                    //     return Err(InherentError::InvalidInherentValue);
                    // }

                    // let expected_aimodelscalc_operations = match Self::aimodelscalc_run(expected_block_number) {
                    //     Ok(operations) => {
                    //         operations
                    //     },
                    //     Err(error) => {
                    //         log::info!("Failed to run AI models calc on check_inherent. error: {:?}", error);
                    //         return Err(InherentError::InvalidInherentValue);
                    //     },
                    // };
                    
                    // if expected_aimodelscalc_operations != *aimodelscalc_operations {
                    //     log::info!("failed check aimodelscalc_operations: {:?}", aimodelscalc_operations);
                    //     log::info!("expected_aimodelscalc_operations: {:?}", expected_aimodelscalc_operations);
                    //     return Err(InherentError::InvalidInherentValue);
                    // }

                    // log::info!("UOMI-ENGINE: Checking inherent OK");
 
                    Ok(())
                }
                _ => Ok(()),
            }
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
        Inputs::<T>::insert(request_id, (block_number, nft_id, nft_required_consensus, nft_execution_max_time, nft_file_cid, input_data, input_file_cid));

        // NOTE: This code is used to maintain the retro-compatibility with old blocks on finney network
        if request_id <= U256::from(47) && nft_required_consensus <= U256::from(1) {
            let mut opoc_blacklist_operations = BTreeMap::<T::AccountId, bool>::new();
            let mut opoc_assignment_operations = BTreeMap::<(U256, T::AccountId), U256>::new();
            let mut nodes_works_operations = BTreeMap::<T::AccountId, BTreeMap<U256, bool>>::new();
            let current_block = frame_system::Pallet::<T>::block_number().into();
            match Self::opoc_assignment_finney_v1(
                &mut opoc_blacklist_operations,
                &mut opoc_assignment_operations,
                &mut nodes_works_operations,
                &request_id,
                &current_block,
                1,
                vec![],
                true
            ) {
                Ok(_) => {
                    Self::opoc_store_operations((
                        opoc_blacklist_operations,
                        opoc_assignment_operations,
                        nodes_works_operations,
                        BTreeMap::<T::AccountId, u32>::new(),
                        BTreeMap::<T::AccountId, u32>::new(),
                        BTreeMap::<RequestId, (Data, u32, u32)>::new()
                    ))?;
                },
                Err(error) => {
                    log::error!("UOMI-ENGINE: Failed to assign request to a random validator for OPoC level 0 on run_request. error: {:?}", error);
                    // NOTE: If assigned is not valid, is not a problem, the request should be assigned by the opoc execution
                },
            };
        }

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
