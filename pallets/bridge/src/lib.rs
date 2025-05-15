#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
    ensure,
    pallet_prelude::*,
    BoundedVec, Parameter,
    weights::Weight,
};
use uomi_primitives::evm::EvmAddress;
use sp_runtime::{
    traits::{Hash, Verify, IdentifyAccount},
    RuntimeDebug, transaction_validity::{
        TransactionValidity, ValidTransaction, InvalidTransaction, TransactionSource,
        TransactionPriority,
    },
    Permill,
};
use sp_runtime::traits::Convert;
use sp_std::prelude::*;
use sp_core::{H160, U256};
use sp_io::hashing::blake2_256;
use pallet_balances::Config as BalancesConfig;

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[derive(Encode, Decode, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    #[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
    #[scale_info(skip_type_params(T))]
    pub struct BridgeTransfer<T: Config> {
        /// Source chain ID (e.g., "ethereum", "polygon")
        pub source_chain_id: BoundedVec<u8, T::MaxDataSize>,
        
        /// Token address on source chain
        pub token_address: BoundedVec<u8, T::MaxDataSize>,
        
        /// Sender address on source chain
        pub sender: BoundedVec<u8, T::MaxDataSize>,
        
        /// Receiver address on Substrate
        pub receiver: T::AccountId,
        
        /// Amount to transfer
        pub amount: u128,
        
        /// Transfer timestamp
        pub timestamp: u64,
        
        /// Verifications count
        pub verifications: u32,
        
        /// Accounts that verified this transfer
        pub verifiers: BoundedVec<T::AccountId, T::MaxValidators>,
    }

    #[derive(Encode, Decode, MaxEncodedLen)]
	pub struct Reasons: u8 {
		/// In order to BRIDGE tokens, we need to withdraw them from the sender
        /// account. This is the reason for the withdrawal.
		const BRIDGE = 0b00100000;
	}

    #[derive(Clone, Encode, Decode, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub enum TransferStatus {
        /// Transfer waiting for sufficient verifications
        Pending,
        
        /// Transfer verified and accepted
        Verified,
        
        /// Transfer executed (tokens minted)
        Executed,
        
        /// Transfer rejected
        Rejected,
    }

    // Define types for unsigned transactions
    #[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub struct SubmitTransferPayload<T: Config> 
    where
        T::AccountId: PartialEq + Eq,
        T::Signature: PartialEq + Eq,
    {
        pub validator: T::AccountId,
        pub source_chain_id: BoundedVec<u8, T::MaxDataSize>,
        pub token_address: BoundedVec<u8, T::MaxDataSize>,
        pub sender: BoundedVec<u8, T::MaxDataSize>,
        pub receiver: T::AccountId,
        pub amount: u128,
        pub nonce: u64,
        pub signature: T::Signature,
    }

    #[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub struct VerifyTransferPayload<T: Config> 
    where
        T::AccountId: PartialEq + Eq,
        T::Signature: PartialEq + Eq,
    {
        pub validator: T::AccountId,
        pub transfer_hash: T::Hash,
        pub signature: T::Signature,
    }

    #[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub struct SubmitOutboundPayload<T: Config> 
    where
        T::AccountId: PartialEq + Eq,
        T::Signature: PartialEq + Eq,
    {
        pub validator: T::AccountId,
        pub dest_chain_id: BoundedVec<u8, T::MaxDataSize>,
        pub token_address: BoundedVec<u8, T::MaxDataSize>,
        pub sender: T::AccountId,
        pub receiver: BoundedVec<u8, T::MaxDataSize>,
        pub amount: u128,
        pub nonce: u64,
        pub signature: T::Signature,
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::error]
    pub enum Error<T> {
        /// Validator already registered
        ValidatorAlreadyExists,
        
        /// Validator doesn't exist
        ValidatorDoesNotExist,
        
        /// Maximum number of validators reached
        TooManyValidators,
        
        /// Transfer doesn't exist
        TransferDoesNotExist,
        
        /// Transfer already verified by this validator
        AlreadyVerified,
        
        /// Transfer was rejected
        TransferRejected,
        
        /// Invalid signature
        InvalidSignature,
        
        /// Data too large
        DataTooLarge,
        
        /// Not authorized
        NotAuthorized,

        /// Not a validator
        NotValidator,

        /// Validation threshold not met
        ValidationThresholdNotMet,
        
        /// Insufficient balance
        InsufficientBalance,
        
        /// Transfer already executed
        AlreadyExecuted,
        
        /// Duplicate nonce
        DuplicateNonce,
    }

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_balances::Config + frame_system::offchain::SendTransactionTypes<Call<Self>> {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Public key type for signature verification
        type PublicKey: Parameter + MaxEncodedLen + Clone + Encode + Decode + IdentifyAccount + 'static;
        
        /// Signature verification for transaction authentication
        type Signature: Verify<Signer = Self::PublicKey> 
                    + Parameter 
                    + Encode 
                    + Decode 
                    + Clone
                    + MaxEncodedLen
                    + 'static;
        
        /// Maximum number of validators
        #[pallet::constant]
        type MaxValidators: Get<u32> + Clone + Send + Sync;
        
        /// Required percentage of validators for a transfer to be considered valid
        /// Expressed as Permill (1_000_000 = 100%)
        #[pallet::constant]
        type RequiredValidatorPercentage: Get<Permill>;

        /// Maximum size for transfer data
        #[pallet::constant]
        type MaxDataSize: Get<u32> + Clone + Send + Sync;
        
        /// Native token ID for the bridge
        #[pallet::constant]
        type NativeTokenId: Get<BoundedVec<u8, Self::MaxDataSize>>;
        
        /// Weight information for extrinsics
        type WeightInfo: WeightInfo;
    }

    // Track which validators have witnessed which transfers
    #[pallet::storage]
    #[pallet::getter(fn validator_transfer_witnesses)]
    pub type ValidatorTransferWitnesses<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat, T::Hash, // hash of the transfer
        Blake2_128Concat, T::AccountId, // validator
        bool, // has witnessed the transfer
        ValueQuery
    >;

    // Keep track of pending transfers to validate
    #[pallet::storage]
    #[pallet::getter(fn pending_transfers)]
    pub type PendingTransfers<T: Config> = StorageValue<
        _,
        BoundedVec<T::Hash, ConstU32<1000>>,
        ValueQuery
    >;

    // Track the last validation block
    #[pallet::storage]
    #[pallet::getter(fn last_validation_block)]
    pub type LastValidationBlock<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;


    #[pallet::event]
    #[pallet::generate_deposit(pub fn deposit_event)]
    pub enum Event<T: Config> {

        NativeBridgedToEvm(T::AccountId, EvmAddress, u128),
    
        // EvmAddress to T::AccountId
        NativeBridgedToSubstrate(EvmAddress, T::AccountId, u128),

    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            // Check if we need to validate transfers periodically
            if n > LastValidationBlock::<T>::get() {
                Self::validate_pending_transfers().unwrap_or_default();
                LastValidationBlock::<T>::put(n);
                Self::deposit_event(Event::TransferValidationPerformed(n));
            }
            
            Weight::zero()
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::submit_inbound_transfer_unsigned { validator, source_chain_id, token_address, sender, receiver, amount, nonce, signature } => {
                    // Check that the validator is registered
                    if !Self::is_validator(validator) {
                        return InvalidTransaction::BadProof.into();
                    }
                    
                    // Check if nonce was already used
                    if UsedNonces::<T>::get(nonce) {
                        return InvalidTransaction::Stale.into();
                    }
                    
                    // Create signature payload
                    let signature_payload = (
                        validator.clone(),
                        source_chain_id.clone(),
                        token_address.clone(),
                        sender.clone(),
                        receiver.clone(),
                        amount,
                        nonce
                    ).encode();
                    
                    // Verify signature
                    if !Self::verify_validator_signature(validator, &signature_payload, signature) {
                        return InvalidTransaction::BadProof.into();
                    }
                    
                    ValidTransaction::with_tag_prefix("BridgePallet")
                        .priority(TransactionPriority::max_value())
                        .and_provides((nonce, validator.clone()))
                        .longevity(64_u64)
                        .propagate(true)
                        .build()
                },
                Call::verify_transfer_unsigned { validator, transfer_hash, signature } => {
                    // Check that the validator is registered
                    if !Self::is_validator(validator) {
                        return InvalidTransaction::BadProof.into();
                    }
                    
                    // Verify the transfer exists
                    if !BridgeTransfers::<T>::contains_key(transfer_hash) {
                        return InvalidTransaction::Custom(1).into();
                    }
                    
                    // Verify signature
                    let signature_payload = (validator.clone(), transfer_hash).encode();
                    if !Self::verify_validator_signature(validator, &signature_payload, signature) {
                        return InvalidTransaction::BadProof.into();
                    }
                    
                    ValidTransaction::with_tag_prefix("BridgePallet")
                        .priority(TransactionPriority::max_value())
                        .and_provides((transfer_hash, validator.clone()))
                        .longevity(64_u64)
                        .propagate(true)
                        .build()
                },
                Call::submit_outbound_transfer_unsigned { validator, dest_chain_id, token_address, sender, receiver, amount, nonce, signature } => {
                    // Check that the validator is registered
                    if !Self::is_validator(validator) {
                        return InvalidTransaction::BadProof.into();
                    }
                    
                    // Create signature payload
                    let signature_payload = (
                        validator.clone(),
                        dest_chain_id.clone(),
                        token_address.clone(),
                        sender.clone(),
                        receiver.clone(),
                        amount,
                        nonce
                    ).encode();
                    
                    // Verify signature
                    if !Self::verify_validator_signature(validator, &signature_payload, signature) {
                        return InvalidTransaction::BadProof.into();
                    }
                    
                    ValidTransaction::with_tag_prefix("BridgePallet")
                        .priority(TransactionPriority::max_value())
                        .and_provides((nonce, validator.clone()))
                        .longevity(64_u64)
                        .propagate(true)
                        .build()
                },
                _ => InvalidTransaction::Call.into(),
            }
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {

        //function 0 "bridgeTokensToEVM"
        #[pallet::weight(T::WeightInfo::bridge_tokens_to_evm())]
        pub fn bridge_native_to_evm(
            origin: OriginFor<T>,
            receiver: EvmAddress,
            amount: u128,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Ensure the sender has enough balance
            ensure!(T::Currency::free_balance(&who) >= amount.into(), Error::<T>::InsufficientBalance);

            //mint_tokens
            Self::mint_tokens(who.clone(), receiver.clone(), amount)?;

            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    // make a function to mint native tokens to an accountID
    pub fn mint_tokens(account_from: T::AccountId, account_to: T::AccountId, amount: u128) -> DispatchResult {
        // Ensure the sender has enough balance
        ensure!(T::Currency::free_balance(&account_from) >= amount.into(), Error::<T>::InsufficientBalance);

        //burn the tokens from the sender
        T::Currency::withdraw(&account_from, amount.into(), Reasons::BRIDGE, ExistenceRequirement::KeepAlive)?;
        
        // Mint the tokens
        T::Currency::deposit_creating(&account_to, amount.into())?;
        
        Ok(())
    }
 
   
}