#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

mod ipfs;
mod storages;
pub mod types;

pub use pallet::*;

use frame_support::pallet_prelude::DispatchClass;

use sp_std::{ vec, vec::Vec };
use core::fmt::Debug;
use frame_support::{
    inherent::{ InherentData, InherentIdentifier, IsFatalError, ProvideInherent },
    parameter_types,
    pallet_prelude::{
        ensure,
        Decode,
        Encode,
        Get,
        IsType,
        MaxEncodedLen,
        OptionQuery,
        RuntimeDebug,
        StorageDoubleMap,
        StorageMap,
        TypeInfo,
        ValueQuery,
        DispatchResultWithPostInfo,
    },
    Blake2_128Concat,
    storage::types::StorageValue,
    traits::{
        fungible::{Mutate as FungibleMutate},
    },
};
use sp_runtime::traits::Convert;
use uomi_primitives::Balance;
use uomi_primitives::TssInterface;
use sp_runtime::traits::AtLeast32BitUnsigned;
use frame_system::{
    ensure_none,
    offchain::{
        AppCrypto,
        CreateSignedTransaction,
        SendUnsignedTransaction,
        SignedPayload,
        Signer,
        SigningTypes,
    },
    pallet_prelude::OriginFor,
};
use sp_core::offchain::KeyTypeId;
use sp_core::U256;
use sp_runtime::traits::{ IdentifyAccount, Saturating, UniqueSaturatedInto };
use sp_runtime::{ DispatchError, DispatchResult };
use sp_std::marker::PhantomData;

// PALLET CRATES
use pallet_staking::Validators;
use storages::{ add_node_pin, remove_node_pin };
use types::{ BlockNumber, Cid, NftId, ExpirationBlockNumber, UsableFromBlockNumber };

extern crate alloc;
use alloc::collections::BTreeSet;

pub const CRYPTO_KEY_TYPE: KeyTypeId = KeyTypeId(*b"ipfs");

//////////////////////////////////////////////////////////////////////////////////
// CRYPTO MODULE /////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////
pub mod crypto {
    use crate::CRYPTO_KEY_TYPE;
    use sp_core::sr25519::Signature as Sr25519Signature;
    use sp_runtime::app_crypto::{ app_crypto, sr25519 };
    use sp_runtime::{ traits::Verify, MultiSignature, MultiSigner };
    use alloc::string::String;

    app_crypto!(sr25519, CRYPTO_KEY_TYPE);

    pub struct AuthId;

    // implemented for ocw-runtime
    impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for AuthId {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::sr25519::Signature;
        type GenericPublic = sp_core::sr25519::Public;
    }

    // implemented for mock runtime in test
    impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
    for AuthId {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::sr25519::Signature;
        type GenericPublic = sp_core::sr25519::Public;
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo)]
pub struct EmptyInherent;

// Prima delle implementazioni del pallet, aggiungi:
#[derive(Encode)]
#[cfg_attr(feature = "std", derive(Debug, Decode))]
pub enum InherentError {
    // Definisci qui i tuoi errori specifici
    InvalidInherentValue,
}

impl IsFatalError for InherentError {
    fn is_fatal_error(&self) -> bool {
        match self {
            InherentError::InvalidInherentValue => true,
        }
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct PinPayload<Public> {
    to_save: Vec<(Cid, (ExpirationBlockNumber, UsableFromBlockNumber))>,
    to_remove: Vec<(Cid, (ExpirationBlockNumber, UsableFromBlockNumber))>,
    public: Public,
}

impl<T: SigningTypes + Config> SignedPayload<T> for PinPayload<T::Public> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}
#[frame_support::pallet]
pub mod pallet {
    use frame_support::{
        pallet_prelude::{
            InvalidTransaction,
            TransactionPriority,
            TransactionSource,
            TransactionValidity,
            ValidTransaction,
        },
        traits::Hooks,
    };
    use frame_system::ensure_signed;
    use sp_runtime::traits::ValidateUnsigned;

    use super::*;

    pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"ipfs-ide";

    parameter_types! {
        pub const MinExpireDuration: u32 = 28800; // bytes
    }

    #[pallet::config]
    pub trait Config: frame_system::Config +
        pallet_staking::Config +
        pallet_session::Config +
        CreateSignedTransaction<Call<Self>> +
        Debug
    {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        #[pallet::constant]
        type IpfsApiUrl: Get<&'static str>;
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

        type Currency: FungibleMutate<Self::AccountId, Balance = Balance>;
        type BlockNumber: AtLeast32BitUnsigned + MaxEncodedLen + Debug;

        #[pallet::constant]
        type TemporaryPinningCost: Get<Balance>;
        
        /// TSS interface for wallet creation
        type TssInterface: uomi_primitives::TssInterface<Self>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        IpfsOperationSuccess {
            operation: IpfsOperation,
            cid: Vec<u8>,
        },
        IpfsOperationFailure { // TODO: Non lo stiamo usando, sarebbe da capire dove ha senso usarlo
            operation: IpfsOperation,
            error: Vec<u8>,
        },
        TemporaryPinCreated {
            cid: Vec<u8>,
            expires_at: BlockNumber<T>,
        },
        PinExpired {
            cid: Vec<u8>,
        },
    }

    #[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, Debug)]
    pub enum IpfsOperation {
        Pin,
        Unpin,
        Get,
        IsPinned,
    }

    // #[derive(Encode, Decode, TypeInfo)]
    #[derive(Encode, Decode, Clone, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub enum ExpirationConfig<B> {
        At(B),
        Never,
    }

    #[pallet::storage]
    pub type NodesPins<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        Cid,
        Blake2_128Concat,
        T::AccountId,
        bool,
        OptionQuery
    >;

    #[pallet::storage]
    pub(super) type InherentDidUpdate<T: Config> = StorageValue<_, bool, ValueQuery>;

    #[pallet::storage]
    pub type AgentsPins<T: Config> = StorageMap<_, Blake2_128Concat, NftId, Cid, ValueQuery>;

    #[pallet::storage]
    pub type CidsStatus<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Cid,
        (ExpirationBlockNumber, UsableFromBlockNumber),
        ValueQuery
    >;

    #[pallet::pallet]
    pub struct Pallet<T>(PhantomData<T>);

    // Errors
    #[pallet::error]
    pub enum Error<T> {
        SomethingWentWrong,
        FundsUnavailable,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumber<T>> for Pallet<T> {
        fn offchain_worker(_: BlockNumber<T>) {
            let _ = Self::process_pins();
        }

        fn on_finalize(_: BlockNumber<T>) {
            // Be sure that the InherentDidUpdate is set to true and reset it to false.
            // This is required to be sure that the inherent function is executed once in the block.
            assert!(InherentDidUpdate::<T>::take(), "IPFS: inherent must be updated once in the block");
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            let current_block_number = frame_system::Pallet::<T>::block_number().into();

            match call {
                // Handle inherent extrinsics
                Call::set_inherent_data { .. } => {
                    ValidTransaction::with_tag_prefix("IpfsPallet")
                        .priority(TransactionPriority::MAX)
                        .and_provides(INHERENT_IDENTIFIER)
                        .longevity(64)
                        .propagate(true)
                        .build()
                }
                // Handle existing submit_processed_pins validation
                Call::submit_processed_pins { .. } => {
                    // Existing validation for submit_processed_pins
                    if source == TransactionSource::External {  // NOTE: This code is used to maintain the retro-compatibility with old blocks on finney network
                        log::info!("IPFS: Rejecting submit_processed_pins unsigned transaction from external origin");
                        return InvalidTransaction::BadSigner.into()
                    }

                    ValidTransaction::with_tag_prefix("IpfsPallet")
                        .priority(TransactionPriority::MAX)
                        .and_provides(&call)
                        .longevity(64)
                        .propagate(true)
                        .build()
                }
                // Reject all other unsigned calls
                _ => InvalidTransaction::Call.into(),
            }
        }
    }

    // Calls
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)]
        pub fn pin_agent(origin: OriginFor<T>, cid: Cid, nft_id: NftId, threshold: u8) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            if AgentsPins::<T>::contains_key(nft_id) {
                log::info!("IPFS: Agent already pinned, contains key");
                let existing_cid = AgentsPins::<T>::get(nft_id);

                if existing_cid == cid {
                    log::info!("IPFS: Agent already pinned, cid is the same");
                    return Err(Error::<T>::SomethingWentWrong.into());
                }

                log::info!("IPFS: Agent already pinned, cid is different");
                log::info!("IPFS: Current block number: {:?}", frame_system::Pallet::<T>::block_number());
                log::info!("IPFS: MinExpireDuration: {:?}", MinExpireDuration::get());

                CidsStatus::<T>::mutate(&existing_cid, |(expires_at, _usable_from)| {
                    let current_block = frame_system::Pallet::<T>::block_number();
                    let new_expiry: u32 = current_block
                        .saturating_add(MinExpireDuration::get().into())
                        .try_into()
                        .unwrap_or(u32::MAX);
                    log::info!("IPFS: Setting expiry to: {}", new_expiry);
                    *expires_at = U256::from(new_expiry);
                    log::info!("IPFS: Expires at after mutation: {}", *expires_at);
                });

                log::info!(
                    "IPFS: Existing CID status after update: {:?}",
                    CidsStatus::<T>::get(&existing_cid)
                );
            } else {
                // Call the TSS Pallet to initiate the wallet creation.
                log::info!("IPFS: Agent not pinned, creating new wallet through TSS Pallet");

                // Check if wallet already exists for this agent
                if !T::TssInterface::agent_wallet_exists(nft_id) {
                    // Create new wallet for the agent
                    if let Err(e) = T::TssInterface::create_agent_wallet(nft_id, threshold) {
                        log::error!("IPFS: Failed to create agent wallet: {:?}", e);
                        return Err(Error::<T>::SomethingWentWrong.into());
                    }
                    log::info!("IPFS: Successfully created wallet for agent {}", nft_id);
                } else {
                    log::info!("IPFS: Wallet already exists for agent {}", nft_id);
                }
            }

            AgentsPins::<T>::insert(nft_id, &cid);
            CidsStatus::<T>::insert(&cid, (U256::zero(), U256::zero()));
            log::info!("IPFS: CID status after insert: {:?}", CidsStatus::<T>::get(&cid));

            Self::deposit_event(Event::IpfsOperationSuccess {
                operation: IpfsOperation::Pin,
                cid: cid.to_vec(),
            });

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(10_000)]
        pub fn pin_file(
            origin: OriginFor<T>,
            cid: Cid,
            duration: BlockNumber<T>
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            let min_duration: BlockNumber<T> = MinExpireDuration::get().into();

            // Check if cid is not empty
            ensure!(!cid.is_empty(), "CID cannot be empty");

            //check if duration is more than 28800 (number of blocks in a day)
            ensure!(duration >= min_duration, "Duration must be more than 28800 blocks");

            let current_block = frame_system::Pallet::<T>::block_number();
            let new_expires_at = current_block.saturating_add(duration);

            if CidsStatus::<T>::contains_key(&cid) {
                CidsStatus::<T>::mutate(&cid, |(expires_at, _usable_from)| {
                    if (new_expires_at.into() > *expires_at) {
                        *expires_at = new_expires_at.into();
                    } else {
                        *expires_at = expires_at.clone();
                    }
                });
            } else {
                CidsStatus::<T>::insert(&cid, (new_expires_at.into(), U256::zero()));
            }

            Self::deposit_event(Event::TemporaryPinCreated {
                cid: cid.to_vec(),
                expires_at: new_expires_at,
            });

            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(10_000)]
        pub fn submit_processed_pins(
            origin: OriginFor<T>,
            payload: PinPayload<T::Public>,
            _signature: T::Signature
        ) -> DispatchResult {
            let _who = ensure_none(origin)?;

            // NOTE: Replace with is_active_validator on TURING!!!
            if !Self::is_validator(&payload.public.clone().into_account()) {
                log::error!("IPFS: Only validators can call submit_processed_pins, ignore submit_processed_pins execution");
                return Err(DispatchError::Other("Only validators can call submit_processed_pins, ignore submit_processed_pins execution"));
            }

            for (cid, _expires_at) in payload.to_save {
                let _ = add_node_pin::<T>(&cid.clone(), &payload.public.clone().into_account());

                Self::deposit_event(Event::IpfsOperationSuccess {
                    operation: IpfsOperation::Pin,
                    cid: cid.to_vec(),
                });
            }

            for (cid, _) in payload.to_remove {
                let _ = remove_node_pin::<T>(cid.clone(), payload.public.clone().into_account());

                Self::deposit_event(Event::IpfsOperationSuccess {
                    operation: IpfsOperation::Unpin,
                    cid: cid.to_vec(),
                });
            }

            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight((10_000, DispatchClass::Mandatory))]
        pub fn set_inherent_data(
            origin: OriginFor<T>,
            operations: (
                Vec<(Cid, (ExpirationBlockNumber, UsableFromBlockNumber))>,
                Vec<(Cid, (ExpirationBlockNumber, UsableFromBlockNumber))>,
            )
        ) -> DispatchResultWithPostInfo {
            log::info!("IPFS: Inherent data called");

            ensure_none(origin)?;
            assert!(
                !InherentDidUpdate::<T>::exists(),
                "Inherent data must be updated only once in the block"
            );
            // get operations to do
            let (usable, to_remove) = operations;

            // set opoc_blacklist_operations
            for (cid, (_expiration_block_number, _usable_from_block_number)) in usable.iter() {
                //if usable, in cidstatus, set usable_from to current block
                CidsStatus::<T>::mutate(cid, |(_expires_at, usable_from)| {
                    let current_block = frame_system::Pallet::<T>::block_number();
                    let block_u32: u32 = current_block.try_into().unwrap_or(u32::MAX);
                    *usable_from = U256::from(block_u32);
                });
            }

            // remove expired pins
            for (cid, (_expires_at, _)) in to_remove.iter() {
                //if expired, remove from cidstatus
                CidsStatus::<T>::remove(cid);
                //in nodesPins remove prefix of the cid
                NodesPins::<T>::remove_prefix(cid, None);
            }

            InherentDidUpdate::<T>::set(true);
            log::info!("IPFS: Inherent data set");
            Ok(().into())
        }
    }

    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = InherentError;
        const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

        fn create_inherent(_data: &InherentData) -> Option<Self::Call> {
            let current_block_number = frame_system::Pallet::<T>::block_number().into();
            log::info!("IPFS: Creating inherent data for block number: {:?}", current_block_number);

            let operations = match Self::ipfs_operations(current_block_number) {
                Ok(operations) => { operations }
                Err(error) => {
                    log::info!("IPFS: Failed to run ipfs_operations. error: {:?}", error);
                    return None;
                }
            };

            Some(Call::set_inherent_data {
                operations,
            })
        }

        fn is_inherent(call: &Self::Call) -> bool {
            matches!(call, Call::set_inherent_data { .. })
        }

        fn check_inherent(call: &Self::Call, _data: &InherentData) -> Result<(), Self::Error> {
            let current_block_number = frame_system::Pallet::<T>::block_number().into();
            let expected_block_number = current_block_number + 1;
            log::info!("IPFS: Checking inherent data for block number: {:?}", expected_block_number);

            match call {
                Call::set_inherent_data { operations } => {
                    let expected_operations = match Self::ipfs_operations(expected_block_number) {
                        Ok(operations) => { operations }
                        Err(error) => {
                            log::info!("IPFS: Failed to run ipfs_operations. error: {:?}", error);
                            return Err(InherentError::InvalidInherentValue);
                        }
                    };
                    let (expected_usable, expected_to_remove) = expected_operations;
                    let (usable, to_remove) = operations;

                    // be sure all items inside usable are inside expected_usable and length is the same
                    if usable.len() != expected_usable.len() {
                        return Err(InherentError::InvalidInherentValue);
                    }
                    for (cid, (expires_at, usable_from)) in usable.iter() {
                        if
                            !expected_usable.contains(
                                &(cid.clone(), (expires_at.clone(), usable_from.clone()))
                            )
                        {
                            return Err(InherentError::InvalidInherentValue);
                        }
                    }

                    // be sure all items inside to_remove are inside expected_to_remove and length is the same
                    if to_remove.len() != expected_to_remove.len() {
                        return Err(InherentError::InvalidInherentValue);
                    }
                    for (cid, (expires_at, usable_from)) in to_remove.iter() {
                        if
                            !expected_to_remove.contains(
                                &(cid.clone(), (expires_at.clone(), usable_from.clone()))
                            )
                        {
                            return Err(InherentError::InvalidInherentValue);
                        }
                    }

                    Ok(())
                }
                _ => Ok(()),
            }
        }
    }

    // Node functions
    impl<T: Config> Pallet<T> {
        // fn charge_storage_fee(who: &T::AccountId) -> Result<Balance, DispatchError> {
        //     let balance = <T as pallet::Config>::Currency::reducible_balance(who, Preserve, Polite);
        //     let fee = T::TemporaryPinningCost::get();
        //     ensure!(balance >= fee, Error::<T>::FundsUnavailable);
        //     <T as pallet::Config>::Currency::burn_from(who, fee, Exact, Polite)?;
        //     Ok(fee)
        // }

        fn get_account_id() -> Result<T::AccountId, DispatchError> {
            let public_keys = sp_io::crypto::sr25519_public_keys(CRYPTO_KEY_TYPE);
            let public_key = match public_keys.get(0) {
                Some(public_key) => public_key,
                None => {
                    log::info!(
                        "IPFS: No local public key available, risking potential slashing! Please check https://docs"
                    );
                    return Err(DispatchError::Other("No local public key available"));
                }
            };
            Ok(T::AccountId::decode(&mut &public_key.encode()[..]).expect("Can decode account id"))
        }

        pub fn is_validator(public: &T::AccountId) -> bool {
            pallet_staking::Validators::<T>::contains_key(public)
        }

        pub fn is_active_validator(account_id: &T::AccountId) -> bool {
            // TODO: For tests we return validators only from pallet_staking::Validators::<T>.
            // In the future we should fix tests to return validators from session::Validators::<T>.
            if cfg!(test) {
                return pallet_staking::Validators::<T>::contains_key(account_id);
            }

            let active_validators = pallet_session::Validators::<T>::get();
            let validator_id = T::ValidatorId::try_from(account_id.clone()).ok().unwrap();

            active_validators.contains(&validator_id)
        }

        fn call_process_pins(
            to_save: Vec<(Cid, (ExpirationBlockNumber, UsableFromBlockNumber))>,
            to_remove: Vec<(Cid, (ExpirationBlockNumber, UsableFromBlockNumber))>
        ) -> Result<(), DispatchError> {
            let signer = Signer::<T, T::AuthorityId>::all_accounts();

            if !signer.can_sign() {
                log::error!("IPFS: No accounts available to sign call_process_pins");
                return Err(DispatchError::Other("IPFS: No accounts available to sign"));
            }

            if !Self::is_active_validator(&Self::get_account_id()?) {
                log::error!("IPFS: Only validators can call submit_processed_pins, skip call_process_pins");
                return Err(DispatchError::Other("IPFS: Only validators can call submit_processed_pins, skip call_process_pins"));
            }

            //send unsigned transaction with signed payload
            let _ = signer.send_unsigned_transaction(
                |acct| PinPayload {
                    to_save: to_save.clone(),
                    to_remove: to_remove.clone(),
                    public: acct.public.clone(),
                },
                |payload, signature| Call::submit_processed_pins { payload, signature }
            );

            Ok(())
        }

        fn process_pin(
            cid: Cid,
            public: &T::AccountId,
            config: (ExpirationBlockNumber, UsableFromBlockNumber),
            to_save: &mut Vec<(Cid, (ExpirationBlockNumber, UsableFromBlockNumber))>
        ) -> Result<(), DispatchError> {
            let (expiry, _usable_from) = config;
            let current_block = frame_system::Pallet::<T>::block_number();
            // Convert U256 to the block number type
            let expiry_block: BlockNumber<T> = expiry.unique_saturated_into();

            if current_block > expiry_block && expiry != U256::zero() {
                log::info!("IPFS: Current block is greater than expiry block");
                return Ok(());
            }

            if !NodesPins::<T>::contains_key(&cid, public) {
                if cfg!(test) {
                    to_save.push((cid, config));
                    return Ok(());
                }
                match Self::offchain_pin_file(cid.clone()) {
                    Ok(_) => { 
                        to_save.push((cid, config));
                    }
                    Err(e) => {
                        log::error!("IPFS: Error pinning file: {:?}", cid);
                        log::error!("IPFS: Error: {:?}", e);
                    }
                }
            }
            Ok(())
        }

        fn process_unpin(
            cid: Cid,
            public: &T::AccountId,
            config: (ExpirationBlockNumber, UsableFromBlockNumber),
            to_remove: &mut Vec<(Cid, (ExpirationBlockNumber, UsableFromBlockNumber))>
        ) -> Result<(), DispatchError> {
            //check nodespins, check if someone has pinned some file that are not in cidstatus, if so unpin it
            if NodesPins::<T>::contains_key(&cid.clone(), public) {
                //cid is present in cidstatus
                if !CidsStatus::<T>::contains_key(&cid) {
                    match Self::offchain_unpin_file(cid.clone()) {
                        Ok(_) => {
                            log::info!("IPFS: File unpinned: {:?}", cid);
                            to_remove.push((cid.clone(), config));
                        }
                        Err(e) => {
                            log::error!("IPFS: Error unpinning file: {:?}", cid);
                            log::error!("IPFS: Error: {:?}", e);
                        }
                    }
                }
            }
            Ok(())
        }

        fn ipfs_operations(
            current_block: U256
        ) -> Result<
            (
                Vec<(Cid, (ExpirationBlockNumber, UsableFromBlockNumber))>,
                Vec<(Cid, (ExpirationBlockNumber, UsableFromBlockNumber))>,
            ),
            DispatchError
        > {
            let mut usable: Vec<(Cid, (ExpirationBlockNumber, UsableFromBlockNumber))> = Vec::new();
            let mut to_remove: Vec<
                (Cid, (ExpirationBlockNumber, UsableFromBlockNumber))
            > = Vec::new();

            //check cids in cidstatus that has expired (avoiding the ones that are persistent with 0 expiry)
            for (cid, (expires_at, usable_from)) in CidsStatus::<T>::iter() {
                if expires_at != U256::zero() && current_block > expires_at {
                    to_remove.push((cid, (expires_at, usable_from)));
                }
            }

            //check cids in cidstatus that are usable (pinned by 50% + 1 of validators)
            for (cid, (expires_at, usable_from)) in CidsStatus::<T>::iter() {
                if Self::is_majority_pinned(&cid) && usable_from == U256::zero() {
                    usable.push((cid, (expires_at, U256::from(0))));
                }
            }

            Ok((usable, to_remove))
        }

        fn process_pins() -> Result<(), DispatchError> {
            let mut to_save: Vec<
                (Cid, (ExpirationBlockNumber, UsableFromBlockNumber))
            > = Vec::new();
            let mut to_remove: Vec<
                (Cid, (ExpirationBlockNumber, UsableFromBlockNumber))
            > = Vec::new();

            let public = Self::get_account_id()?;

            //iter cidsStatus
            for (cid, (expires_at, usable_from)) in CidsStatus::<T>::iter() {
                if cid.is_empty() {
                    log::info!("IPFS: Skipping empty CID");
                    continue;
                }
                Self::process_pin(cid, &public, (expires_at, usable_from), &mut to_save)?;
            }

            for (cid, (expires_at, usable_from)) in CidsStatus::<T>::iter() {
                Self::process_unpin(cid, &public, (expires_at, usable_from), &mut to_remove)?;
            }

            //dont call process_pins if there are no pins to process, to avoid making an unnecessary transaction
            if to_save.is_empty() && to_remove.is_empty() {
                log::info!("IPFS: No pins or unpins to process");
                return Ok(());
            }

            Self::call_process_pins(to_save, to_remove)?;

            Ok(())
        }

        fn offchain_unpin_file(cid: Cid) -> Result<bool, sp_runtime::offchain::http::Error> {
            ipfs::offchain_unpin_file::<T>(&cid).map(|_| true)
        }

        fn offchain_pin_file(cid: Cid) -> Result<bool, sp_runtime::offchain::http::Error> {
            ipfs::offchain_pin_file::<T>(&cid).map(|_| true)
        }

        pub fn get_agent_cid(nft_id: NftId) -> Result<Cid, DispatchError> {
            let cid = AgentsPins::<T>::get(nft_id);
            if cid.is_empty() {
                return Err(sp_runtime::DispatchError::Other("error"));
            }
            Ok(cid)
        }

        pub fn get_cid_status(
            cid: &Cid
        ) -> Result<(ExpirationBlockNumber, UsableFromBlockNumber), DispatchError> {
            let status = CidsStatus::<T>::get(cid);
            Ok(status)
        }

        pub fn get_file(cid: &Cid) -> Result<Vec<u8>, sp_runtime::offchain::http::Error> {
            log::info!("IPFS: Getting file from CID: {:?}", cid);
            // Check if it's expired (or if it never expires) and check if it's usable
            let (expires_at, usable_from) = CidsStatus::<T>::get(&cid);
            let current_block = frame_system::Pallet::<T>::block_number();

            //if expire_at is 0, it means it's a persistent pin, otherwise it's a temporary pin to check if it's expired
            if expires_at != U256::zero() && current_block > expires_at.unique_saturated_into() {
                return Err(sp_runtime::offchain::http::Error::Unknown);
            }
            log::info!("IPFS: CID is not expired");

            // Check if it's usable
            if usable_from == U256::zero() || current_block < usable_from.unique_saturated_into() {
                return Err(sp_runtime::offchain::http::Error::Unknown);
            }
            log::info!("IPFS: CID is usable");

            Self::get_file_from_cid(&cid)
        }

        fn get_file_from_cid(cid: &Cid) -> Result<Vec<u8>, sp_runtime::offchain::http::Error> {
            let output = ipfs::get_file_from_cid::<T>(cid);

            Self::deposit_event(Event::IpfsOperationSuccess {
                operation: IpfsOperation::Get,
                cid: cid.to_vec(),
            });

            Ok(output?)
        }

        pub fn is_majority_pinned(cid: &Cid) -> bool {
            // Get all validators
            let validators = Validators::<T>
                ::iter()
                .map(|(v, _)| v)
                .collect::<Vec<_>>();

            // If no validators, return false
            if validators.is_empty() {
                return false;
            }

            // Calculate required majority (50% + 1)
            let total_validators = validators.len();
            let mut required_majority = total_validators / 2 + 1;
            if total_validators <= 3 { // small chain probably is a local testnet
                required_majority = 1;
            }

            // Get all validators who pinned this CID
            let pinned_validators: BTreeSet<_> = NodesPins::<T>
                ::iter_prefix(cid)
                .map(|(validator, _)| validator)
                .collect();

            // If no pins at all, return false
            if pinned_validators.is_empty() {
                return false;
            }

            // Count how many validators from the current set have pinned
            let pinned_count = validators
                .iter()
                .filter(|v| pinned_validators.contains(v))
                .count();

            // Return true if we have majority
            pinned_count >= required_majority
        }
    }
}
