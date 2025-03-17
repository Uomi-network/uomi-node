#![cfg_attr(not(feature = "std"), no_std)]
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
    ensure,
    pallet_prelude::*,
    BoundedVec, Parameter,
    weights::Weight,
};
use sp_runtime::Saturating;
use sp_std::fmt::Debug;
use frame_system::{ensure_root, ensure_none, pallet_prelude::*};
use scale_info::TypeInfo;
use sp_runtime::{
    traits::{Hash, Verify, IdentifyAccount},
    RuntimeDebug, transaction_validity::{
        TransactionValidity, ValidTransaction, InvalidTransaction, TransactionSource,
        TransactionPriority,
    },
    Permill,
};
use sp_runtime::traits::Convert;
use sp_staking::offence::ReportOffence;
use sp_staking::offence::Offence;
use sp_std::prelude::*;
use sp_staking::{EraIndex, SessionIndex};
//perbill
use sp_runtime::Perbill;

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

#[cfg(feature = "std")]
pub mod rpc;

#[cfg(feature = "std")]
pub use rpc::*;

// Export the Runtime API
pub mod runtime_api;
pub use crate::runtime_api::*;

// Export the needed types for RPC
pub use pallet::RelayerEventInput;


#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[derive(RuntimeDebug)]
    pub struct MaliciousBehaviourOffence<T: Config> {
        /// The session index in which the offence occurred.
        pub session_index: SessionIndex,
        /// The size of the validator set at the time of the offence.
        pub validator_set_count: u32,
        /// The offender's validator ID.
        pub offender: pallet_session::historical::IdentificationTuple<T>,
    }
    
    // Implementazione per Offence
    impl<T: Config> Offence<pallet_session::historical::IdentificationTuple<T>> for MaliciousBehaviourOffence<T> 
    where
        T: pallet_session::historical::Config,
        T: pallet_session::Config<ValidatorId = <T as frame_system::Config>::AccountId>,
    {
        const ID: [u8; 16] = *b"relayer:inactive";
        type TimeSlot = SessionIndex;
    
        fn offenders(&self) -> Vec<pallet_session::historical::IdentificationTuple<T>> {
            vec![self.offender.clone()]
        }
    
        fn session_index(&self) -> SessionIndex {
            self.session_index
        }
    
        fn validator_set_count(&self) -> u32 {
            self.validator_set_count
        }
    
        fn time_slot(&self) -> Self::TimeSlot {
            self.session_index
        }
    
        fn slash_fraction(&self, _offenders_count: u32) -> Perbill {
            // Ritorna 5% slash indipendentemente dal numero di offenders
            Perbill::from_percent(5)
        }
    }

    #[derive(Encode, Decode, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    #[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
    #[scale_info(skip_type_params(T))]
    pub struct ChainEvent<T: Config> {
        /// Chain ID (es. "ethereum", "polygon", ecc.)
        pub chain_id: BoundedVec<u8, T::MaxDataSize>,
        
        /// Block number
        pub block_number: u64,
        
        /// Contract address
        pub contract_address: BoundedVec<u8, T::MaxDataSize>,
        
        /// Event data
        pub event_data: BoundedVec<u8, T::MaxDataSize>,
        
        /// Event timestamp
        pub timestamp: u64,
        
        /// Verifications count
        pub verifications: u32,
        
        /// Accounts that verified this event
        pub verifiers: BoundedVec<T::AccountId, T::MaxRelayers>,
    }

    #[derive(Clone, Encode, Decode, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub enum ChainEventStatus {
        /// Event waiting for sufficient verifications
        Pending,
        
        /// Event verified and accepted
        Verified,
        
        /// Event rejected
        Rejected,
        
        /// Event successfully executed
        Executed,
    }

    #[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    #[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
    pub struct RelayerEventInput {
        pub chain_id: Vec<u8>,
        pub block_number: u64,
        pub contract_address: Vec<u8>,
        pub event_data: Vec<u8>,
    }

    // Definisci i tipi per le transazioni unsigned
    #[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub struct SubmitEventPayload<T: Config> 
    where
        T::AccountId: PartialEq + Eq,
        T::Signature: PartialEq + Eq,
    {
        pub relayer: T::AccountId,
        pub chain_id: BoundedVec<u8, T::MaxDataSize>,
        pub block_number: u64,
        pub contract_address: BoundedVec<u8, T::MaxDataSize>,
        pub event_data: BoundedVec<u8, T::MaxDataSize>,
        pub signature: T::Signature,
    }

    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
    pub struct VerifyEventPayload<T: Config>
    where
        T::AccountId: PartialEq + Eq,
        T::Signature: PartialEq + Eq,
    {
        pub relayer: T::AccountId,
        pub event_hash: T::Hash,
        pub signature: T::Signature,
    }

    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
    pub struct ExecuteEventPayload<T: Config>
    where
        T::Signature: PartialEq + Eq,
    {
        pub event_hash: T::Hash,
        pub signature: T::Signature,
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::error]
    pub enum Error<T> {
        /// Relayer already registered
        RelayerAlreadyExists,
        
        /// Relayer doesn't exist
        RelayerDoesNotExist,
        
        /// Maximum number of relayers reached
        TooManyRelayers,
        
        /// Event doesn't exist
        EventDoesNotExist,
        
        /// Event already verified by this relayer
        AlreadyVerified,
        
        /// Event was rejected
        EventRejected,
        
        /// Inconsistent event data
        InconsistentEventData,
        
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

        // Failed to slash validator
        SlashingFailed,
    }

    #[pallet::config]
    pub trait Config: frame_system::Config + Sync + Send + TypeInfo + Debug + Eq + Clone 
    + pallet_staking::Config 
    + pallet_session::Config<ValidatorId = <Self as frame_system::Config>::AccountId>
    + pallet_session::historical::Config
    + pallet_offences::Config
    + frame_system::offchain::SendTransactionTypes<Call<Self>> {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Public key type for signature verification
        type PublicKey: Parameter + MaxEncodedLen + Clone + Encode + Decode + IdentifyAccount + 'static;
        
        /// Signature verification for RPC authentication
        type Signature: Verify<Signer = Self::PublicKey> 
                    + Parameter 
                    + Encode 
                    + Decode 
                    + Clone
                    + MaxEncodedLen
                    + 'static;
        
        /// Maximum number of relayers
        #[pallet::constant]
        type MaxRelayers: Get<u32> + Clone + Send + Sync;
        
        /// Required percentage of validators for an event to be considered valid
        /// Expressed as Permill (1_000_000 = 100%)
        #[pallet::constant]
        type RequiredValidatorPercentage: Get<Permill>;

        /// Maximum size for event data
        #[pallet::constant]
        type MaxDataSize: Get<u32> + Clone + Send + Sync;
        
        /// Weight information for extrinsics
        type WeightInfo: WeightInfo;

        type OffenceReporter: ReportOffence<
        Self::AccountId,
        pallet_session::historical::IdentificationTuple<Self>,
        MaliciousBehaviourOffence<Self>
         >;

        // Handler per le offese
        // type OnOffenceHandler: OnOffenceHandler<Self::AccountId, Self::AccountId, MaliciousBehaviourOffence<Self>>;
    }

    // Registra quali validatori hanno visto quali eventi, per ogni evento
    #[pallet::storage]
    #[pallet::getter(fn validator_event_witnesses)]
    pub type ValidatorEventWitnesses<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat, T::Hash, // hash dell'evento
        Blake2_128Concat, T::AccountId, // validatore
        bool, // ha visto l'evento
        ValueQuery
    >;

    #[pallet::storage]
    #[pallet::getter(fn validator_activation_era)]
    pub type ValidatorActivationEra<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId, // validator
        EraIndex,     // era in cui il validatore è diventato attivo
        ValueQuery    // Default a 0
    >;

    #[pallet::storage]
    #[pallet::getter(fn validator_response_metrics)]
    pub type ValidatorResponseMetrics<T: Config> = StorageMap<
        _,
        Blake2_128Concat, 
        T::AccountId, // validator 
        (u32, u32),   // (events_responded, total_events)
        ValueQuery    // Default to (0, 0)
    >;

    // When a new era begins, we should reset the metrics
    #[pallet::storage]
    #[pallet::getter(fn current_era)]
    pub type CurrentEra<T: Config> = StorageValue<_, EraIndex, ValueQuery>;

    // Mantieni una lista di eventi pendenti da validare
    #[pallet::storage]
    #[pallet::getter(fn pending_events)]
    pub type PendingEvents<T: Config> = StorageValue<
        _,
        BoundedVec<T::Hash, ConstU32<1000>>,
        ValueQuery
    >;

    // Riferimento all'ultima sessione in cui è avvenuta la validazione
    #[pallet::storage]
    #[pallet::getter(fn last_validation_block)]
    pub type LastValidationBlock<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn relayers)]
    pub type Relayers<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        T::PublicKey,
        OptionQuery
    >;

    #[pallet::storage]
    #[pallet::getter(fn relayer_count)]
    pub type RelayerCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn chain_events)]
    pub type ChainEvents<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::Hash,
        ChainEvent<T>,
        OptionQuery
    >;

    #[pallet::storage]
    #[pallet::getter(fn event_status)]
    pub type EventStatus<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::Hash,
        ChainEventStatus,
        ValueQuery,
        DefaultEventStatus
    >;

    #[pallet::type_value]
    pub fn DefaultEventStatus() -> ChainEventStatus {
        ChainEventStatus::Pending
    }

    // Index to find events by contract and chainId
    #[pallet::storage]
    pub type EventsByContract<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat, BoundedVec<u8, T::MaxDataSize>, // chain_id
        Blake2_128Concat, BoundedVec<u8, T::MaxDataSize>, // contract_address
        BoundedVec<T::Hash, ConstU32<100>>,
        ValueQuery
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub fn deposit_event)]
    pub enum Event<T: Config> {
        /// New relayer registered
        RelayerAdded(T::AccountId),
        
        /// Relayer removed
        RelayerRemoved(T::AccountId),
        
        
        /// New event submitted
        EventSubmitted(T::Hash, BoundedVec<u8, T::MaxDataSize>, T::AccountId), // (event_hash, chain_id, relayer)
        
        /// Event verified
        EventVerified(T::Hash, T::AccountId),
        
        /// Event ready for execution
        EventReady(T::Hash),
        
        /// Event executed
        EventExecuted(T::Hash),

        /// Event validation triggered
        EventValidationPerformed(BlockNumberFor<T>),

        /// Validator slashed for low response rate
        ValidatorSlashed(T::AccountId, Permill), 
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            let mut consumed_weight = Weight::zero();
            
            // Configurazione: validazione ogni 10 blocchi
            const VALIDATION_INTERVAL: u32 = 10;
            
            let last_block = Self::last_validation_block();
            
            // Valida se è passato l'intervallo di blocchi
            let blocks_elapsed = n.saturating_sub(last_block);
            let should_validate = blocks_elapsed >= BlockNumberFor::<T>::from(VALIDATION_INTERVAL);
            
            if should_validate {
                // Esegui la validazione degli eventi pendenti
                let _ = Self::validate_pending_events();
                
                // Aggiorna i timestamp di validazione
                LastValidationBlock::<T>::put(n);
                
                // Emetti un evento
                Self::deposit_event(Event::<T>::EventValidationPerformed(n));
                
                consumed_weight = consumed_weight.saturating_add(<T as pallet::Config>::WeightInfo::validate_events());
            }
            
            // Verifica se è iniziata una nuova era e, in tal caso, processa gli slash
            if let Some(current_era) = pallet_staking::Pallet::<T>::current_era() {
                let stored_era = CurrentEra::<T>::get();
                
                // Se siamo in una nuova era, processa i validatori
                if current_era > stored_era {
                    // Aggiorna l'era corrente registrata
                    CurrentEra::<T>::put(current_era);

                    Self::cleanup_inactive_validators();
                    
                    // Ottieni la lista dei validatori attivi
                    let validators: Vec<T::AccountId> = pallet_session::Validators::<T>::get();
                    
                    // Per ogni validatore, controlla il tasso di risposta
                    for validator in validators.clone() {
                        let (responded, total) = ValidatorResponseMetrics::<T>::get(&validator);
                        
                        // Ottieni l'era di attivazione del validatore
                        let activation_era = ValidatorActivationEra::<T>::get(&validator);
                        
                        // Procedi solo se ci sono stati eventi da processare e il validatore era attivo per l'intera era
                        // oppure per una parte significativa di essa (es. attivo per almeno metà dell'era)
                        if total > 0 && (activation_era < stored_era || (activation_era == stored_era && current_era - activation_era > 1)) {
                            let response_rate = Permill::from_rational(responded, total);
                            let threshold = Permill::from_percent(50);
                            
                            // Slash solo se il rate è sotto il 50%
                            if response_rate < threshold {
                                let validator_set_count = validators.clone().len() as u32;
                                let session_index = <pallet_session::Pallet<T>>::current_index();
                                
                                // Ottieni l'identificazione completa per il validatore
                                if let Some(offender) = <T as pallet_session::historical::Config>::FullIdentificationOf::convert(validator.clone()) {
                                    // Crea l'offesa
                                    let offence = MaliciousBehaviourOffence::<T> {
                                        validator_set_count,
                                        session_index,
                                        offender: (validator.clone(), offender),
                                    };
                                    
                                    // Riporta l'offesa utilizzando l'OffenceReporter configurato
                                    let reporters = vec![].into(); // Nessun reporter per lo slashing automatico
                                    let _ = T::OffenceReporter::report_offence(reporters, offence);
                                    
                                    // Emetti l'evento
                                    Self::deposit_event(Event::<T>::ValidatorSlashed(validator.clone(), response_rate));
                                }
                            }
                        }
                        
                        // Resetta le metriche per la prossima era
                        ValidatorResponseMetrics::<T>::insert(&validator, (0, 0));
                    }
                    
                    // Aggiungi peso per lo slashing 
                    consumed_weight = consumed_weight.saturating_add(<T as pallet::Config>::WeightInfo::process_era_end().saturating_mul(validators.len() as u64));
                }
            }
            
            consumed_weight
        }

    }


    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            log::info!("validate");
            match call {
                Call::submit_event_unsigned { relayer, chain_id, block_number, contract_address, event_data, signature } => {
                   
                    // Controlla che il relayer sia registrato
                    if !Self::is_relayer(relayer) {
                        return InvalidTransaction::BadProof.into();
                    }
                    
                    // Estrai i dati per la firma
                    let signature_payload = (
                        relayer.clone(),
                        chain_id.clone(),
                        block_number,
                        contract_address.clone(),
                        event_data.clone()
                    ).encode();
                    
                    // Verifica la firma
                    if !Self::verify_relayer_signature(relayer, &signature_payload, &signature) {
                        return InvalidTransaction::BadProof.into();
                    }

                    let unique_id = T::Hashing::hash_of(&(
                        relayer.clone(),
                        &chain_id,
                        block_number,
                        &contract_address
                    ));
                    
                    ValidTransaction::with_tag_prefix("RelayerOrchestration")
                        .priority(TransactionPriority::max_value())
                        .and_provides(
                            unique_id
                        )
                        .longevity(64_u64)
                        .propagate(true)
                        .build()
                },
                Call::register_relayer_unsigned { relayer, public_key, validator_signature } => {
                    log::info!("validate_sub");
                    // Verifica che il relayer non sia già registrato
                    if Self::is_relayer(relayer) {
                        return InvalidTransaction::BadProof.into();
                    }
                    
                    // Verifica che il relayer sia anche un validatore
                    if !Self::address_is_active_validator(relayer) {
                        return InvalidTransaction::BadProof.into();
                    }
                    
                    // Verifica che la firma sia valida
                    let payload = (b"register_relayer", relayer.clone(), public_key.clone()).encode();
                    let account_id = public_key.clone().into_account();


                    if !validator_signature.verify(payload.as_slice(), &account_id) {
                        log::info!("validate_sub_err");
                        return InvalidTransaction::BadProof.into();
                    }
                    log::info!("validate_sub_ok");
                    ValidTransaction::with_tag_prefix("RelayerOrchestrationPallet")
                        .priority(TransactionPriority::MAX)
                        .and_provides(&call)
                        .longevity(64_u64)
                        .propagate(true)
                        .build()
                }
                Call::remove_relayer_unsigned { relayer, validator_signature } => {
                    // Verifica che il relayer esista
                    if !Self::is_relayer(relayer) {
                        return InvalidTransaction::BadProof.into();
                    }
                    
                    // Verifica che il relayer sia anche un validatore
                    if !Self::address_is_active_validator(relayer) {
                        return InvalidTransaction::BadProof.into();
                    }
                    
                    // Verifica che la firma sia valida
                    let public_key = Self::get_relayer_public_key(relayer).ok_or(InvalidTransaction::BadProof)?;
                    let payload = (b"remove_relayer", relayer.clone()).encode();
                    let account_id = public_key.clone().into_account();
                    
                    if !validator_signature.verify(payload.as_slice(), &account_id) {
                        return InvalidTransaction::BadProof.into();
                    }
                    
                    ValidTransaction::with_tag_prefix("RelayerOrchestration")
                        .priority(TransactionPriority::max_value())
                        .and_provides(relayer)
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
        /// Submit an event without 
        #[pallet::call_index(0)]
        #[pallet::weight(<T as pallet::Config>::WeightInfo::submit_event())]
        pub fn submit_event_unsigned(
            origin: OriginFor<T>,
            relayer: T::AccountId,
            chain_id: BoundedVec<u8, T::MaxDataSize>,
            block_number: u64,
            contract_address: BoundedVec<u8, T::MaxDataSize>,
            event_data: BoundedVec<u8, T::MaxDataSize>,
            _signature: T::Signature,
        ) -> DispatchResult {
            ensure_none(origin)?;
            
            // Verifica che il relayer sia anche un validatore
            ensure!(Self::address_is_active_validator(&relayer), Error::<T>::NotValidator);
            
            // Calcola l'hash che identificherà l'evento
            let event_hash = Self::calculate_event_hash(
                &chain_id,
                block_number,
                &contract_address,
                &event_data
            );
            
            // Verifica se l'evento esiste già e lo crea se necessario
            if !ChainEvents::<T>::contains_key(&event_hash) {
                // Create the event
                let timestamp = Self::now();
                let verifiers = BoundedVec::<T::AccountId, T::MaxRelayers>::try_from(vec![relayer.clone()])
                    .map_err(|_| Error::<T>::TooManyRelayers)?;
                
                let event = ChainEvent {
                    chain_id: chain_id.clone(),
                    block_number,
                    contract_address: contract_address.clone(),
                    event_data: event_data.clone(),
                    timestamp,
                    verifications: 1,
                    verifiers,
                };
                
                // Save the event
                ChainEvents::<T>::insert(event_hash, event);
                EventStatus::<T>::insert(event_hash, ChainEventStatus::Pending);
                
                // Add event to index
                EventsByContract::<T>::try_mutate(
                    &chain_id,
                    &contract_address,
                    |events| -> Result<(), Error<T>> {
                        events.try_push(event_hash).map_err(|_| Error::<T>::TooManyRelayers)?;
                        Ok(())
                    }
                )?;
                
                // Aggiungi l'evento alla lista dei pendenti
                PendingEvents::<T>::try_mutate(|events| -> Result<(), Error<T>> {
                    events.try_push(event_hash).map_err(|_| Error::<T>::TooManyRelayers)?;
                    Ok(())
                })?;
            } else {
                // L'evento esiste già, aggiorna i validatori
                ChainEvents::<T>::try_mutate(event_hash, |maybe_event| -> Result<(), Error<T>> {
                    let event = maybe_event.as_mut().ok_or(Error::<T>::EventDoesNotExist)?;
                    
                    // Verifica che questo validatore non abbia già verificato l'evento
                    if !event.verifiers.contains(&relayer) {
                        event.verifications += 1;
                        event.verifiers.try_push(relayer.clone()).map_err(|_| Error::<T>::TooManyRelayers)?;
                    }
                    
                    Ok(())
                })?;
            }
            
            // Registra questo validatore come testimone dell'evento
            ValidatorEventWitnesses::<T>::insert(event_hash, relayer.clone(), true);
            
            Self::deposit_event(Event::EventSubmitted(event_hash, chain_id, relayer));
            Ok(())
        }
        
        
        #[pallet::call_index(1)]
        #[pallet::weight(<T as pallet::Config>::WeightInfo::register_relayer())]
        pub fn register_relayer_unsigned(
            origin: OriginFor<T>,
            relayer: T::AccountId,
            public_key: T::PublicKey,
            validator_signature: T::Signature,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::info!("Registering relayer: {:?}", relayer);
            
            // Verifica che la chiave pubblica del relayer corrisponda alla chiave che ha generato la firma
            let payload = (b"register_relayer", relayer.clone(), public_key.clone()).encode();
            let account_id = public_key.clone().into_account();
            log::info!("2");
            
            // Verifica che la firma sia creata dalla stessa chiave che si vuole registrare
            ensure!(validator_signature.verify(payload.as_slice(), &account_id), Error::<T>::InvalidSignature);
            log::info!("3");
            // Verifica se relayer esiste già
            ensure!(!Relayers::<T>::contains_key(&relayer), Error::<T>::RelayerAlreadyExists);
            log::info!("4");
            //verifica che il relayer sia anche un validator in pallet-staking
            let is_validator = Self::address_is_active_validator(&relayer);
            ensure!(is_validator, Error::<T>::NotValidator);
            log::info!("5");
            // Verifica limite relayers
            let count = RelayerCount::<T>::get();
            ensure!(count < T::MaxRelayers::get(), Error::<T>::TooManyRelayers);
            log::info!("6");
            // Registra il relayer
            Relayers::<T>::insert(&relayer, public_key);
            RelayerCount::<T>::put(count + 1);
            log::info!("7");
            Self::deposit_event(Event::RelayerAdded(relayer));
            log::info!("8");
            Ok(())
        }
        
        #[pallet::call_index(2)]
        #[pallet::weight(<T as pallet::Config>::WeightInfo::remove_relayer())]
        pub fn remove_relayer_unsigned(
            origin: OriginFor<T>,
            relayer: T::AccountId,
            validator_signature: T::Signature,
        ) -> DispatchResult {
            ensure_none(origin)?;
            
            // Verifica che il relayer esista
            ensure!(Relayers::<T>::contains_key(&relayer), Error::<T>::RelayerDoesNotExist);
            
            // Ottieni la chiave pubblica del relayer
            let public_key = Relayers::<T>::get(&relayer).ok_or(Error::<T>::RelayerDoesNotExist)?;
            
            // Crea e verifica il payload
            let payload = (b"remove_relayer", relayer.clone()).encode();
            let account_id = public_key.clone().into_account();
            
            // Verifica che la firma provenga dalla stessa chiave registrata come relayer
            ensure!(validator_signature.verify(payload.as_slice(), &account_id), Error::<T>::InvalidSignature);
            
            // Rimuovi il relayer
            Relayers::<T>::remove(&relayer);
            RelayerCount::<T>::mutate(|count| *count -= 1);
            
            Self::deposit_event(Event::RelayerRemoved(relayer));
            Ok(())
        }

        /// Call manually to validate pending events.
        /// This is automatically called on session change, but can be called manually if needed.
        #[pallet::call_index(3)]
        #[pallet::weight(<T as pallet::Config>::WeightInfo::validate_events())]
        pub fn force_validate_events(
            origin: OriginFor<T>
        ) -> DispatchResult {
            ensure_root(origin)?;
            
            Self::validate_pending_events()?;

            Self::deposit_event(Event::EventValidationPerformed(<frame_system::Pallet<T>>::block_number()));
            Ok(())
        }

        #[pallet::call_index(4)]
        #[pallet::weight(<T as pallet::Config>::WeightInfo::process_era_end())]
        pub fn force_process_era(
            origin: OriginFor<T>
        ) -> DispatchResult {
            ensure_root(origin)?;
            
            // Simula il comportamento dell'era change
            if let Some(current_era) = pallet_staking::Pallet::<T>::current_era() {
                let stored_era = CurrentEra::<T>::get();
                
                // Forza l'elaborazione anche se siamo nella stessa era
                if current_era >= stored_era {
                    // Aggiorna l'era corrente registrata
                    CurrentEra::<T>::put(current_era);
                    
                    // Ottieni la lista dei validatori attivi
                    let validators: Vec<T::AccountId> = pallet_session::Validators::<T>::get();
                    
                    // Per ogni validatore, controlla il tasso di risposta
                    for validator in validators {
                        let (responded, total) = ValidatorResponseMetrics::<T>::get(&validator);
                        
                        // Procedi solo se ci sono stati eventi da processare
                        if total > 0 {
                            let response_rate = Permill::from_rational(responded, total);
                            let threshold = Permill::from_percent(50);
                            
                            // Slash solo se il rate è sotto il 50%
                            if response_rate < threshold {
                                
                                let validator_set_count = <pallet_session::Pallet<T>>::validators().len() as u32;
                                let session_index = <pallet_session::Pallet<T>>::current_index();
                                
                                // Ottieni l'identificazione completa per il validatore
                                if let Some(offender) = <T as pallet_session::historical::Config>::FullIdentificationOf::convert(validator.clone()) {
                                    // Crea l'offesa
                                    let offence = MaliciousBehaviourOffence::<T> {
                                        validator_set_count,
                                        session_index,
                                        offender: (validator.clone(), offender),
                                    };
                                    
                                    // Riporta l'offesa utilizzando l'OffenceReporter configurato
                                    let reporters = vec![].into(); // Nessun reporter per lo slashing automatico
                                    let _ = T::OffenceReporter::report_offence(reporters, offence);
                                    
                                    // Emetti l'evento
                                    Self::deposit_event(Event::<T>::ValidatorSlashed(validator.clone(), response_rate));
                                }
                            }
                            
                            // Resetta le metriche per la prossima era
                            ValidatorResponseMetrics::<T>::insert(&validator, (0, 0));
                        }
                    }
                }
            }
            
            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    // Calcola l'hash di un evento in modo deterministico
    fn calculate_event_hash(
        chain_id: &BoundedVec<u8, T::MaxDataSize>,
        block_number: u64,
        contract_address: &BoundedVec<u8, T::MaxDataSize>,
        event_data: &BoundedVec<u8, T::MaxDataSize>,
    ) -> T::Hash {
        T::Hashing::hash_of(&(chain_id, block_number, contract_address, event_data))
    }

    fn cleanup_inactive_validators() {
        // Ottieni la lista di tutti i validatori attivi
        let active_validators: Vec<T::AccountId> = pallet_session::Validators::<T>::get();
        
        // Rimuovi i dati dei validatori che non sono più attivi
        let all_tracked_validators: Vec<T::AccountId> = ValidatorActivationEra::<T>::iter()
            .map(|(validator, _)| validator)
            .collect();
        
        for validator in all_tracked_validators {
            if !active_validators.contains(&validator) {
                // Il validatore non è più attivo, rimuovi i suoi dati
                ValidatorActivationEra::<T>::remove(&validator);
                ValidatorResponseMetrics::<T>::remove(&validator);
            }
        }
    }

    // Valida gli eventi pendenti
    fn validate_pending_events() -> DispatchResult {
        // Ottieni i validatori attuali
        let validators: Vec<T::AccountId> = pallet_session::Validators::<T>::get();
        let validator_count = validators.len() as u32;
        
        // Verifica se ci sono nuovi validatori e registra la loro era di attivazione
        if let Some(current_era) = pallet_staking::Pallet::<T>::current_era() {
            for validator in validators.iter() {
                if ValidatorActivationEra::<T>::get(validator) == 0 {
                    // Se il validatore non ha un'era di attivazione registrata, registrala ora
                    ValidatorActivationEra::<T>::insert(validator, current_era);
                }
            }
        }
        
        // Soglia per la validazione (51%)
        let threshold = T::RequiredValidatorPercentage::get().mul_floor(validator_count);
        
        // Ottieni gli eventi pendenti
        let pending_events = PendingEvents::<T>::get();
        let mut validated_events = Vec::new();
        
        // Verifica ogni evento
        for event_hash in pending_events.iter() {
            let mut validation_count = 0;
            
            // Conta le validazioni per questo evento e registra i validatori che non hanno risposto
            for validator in validators.iter() {
                let has_witnessed = ValidatorEventWitnesses::<T>::get(event_hash, &validator);
                
                if has_witnessed {
                    validation_count += 1;
                    ValidatorResponseMetrics::<T>::mutate(validator, |(responded, total)| {
                        *responded += 1;
                        *total += 1;
                    }); 
                } else {
                    // Update the validator's response metrics (missed an event)
                    ValidatorResponseMetrics::<T>::mutate(validator, |(_responded, total)| {
                        *total += 1;
                    });
                }
            }
            
            // Se l'evento ha abbastanza validazioni, viene confermato
            if validation_count >= threshold {
                EventStatus::<T>::insert(event_hash, ChainEventStatus::Verified);
                Self::deposit_event(Event::EventReady(*event_hash));
                validated_events.push(*event_hash);
            }
        }
        
        // Rimuovi gli eventi validati dalla lista dei pendenti
        PendingEvents::<T>::try_mutate(|events| -> Result<(), Error<T>> {
            for hash in validated_events {
                if let Some(pos) = events.iter().position(|h| h == &hash) {
                    events.swap_remove(pos);
                }
            }
            Ok(())
        })?;
        
        Ok(())
    }      

    /// Get current timestamp
    pub fn now() -> u64 {
        let now = <frame_system::Pallet<T>>::block_number();
        TryInto::<u64>::try_into(now).ok().unwrap_or(0)
    }
    
    /// Check if an account is a relayer
    pub fn is_relayer(who: &T::AccountId) -> bool {
        Relayers::<T>::contains_key(who)
    }

    /// Get a relayer's public key
    pub fn get_relayer_public_key(who: &T::AccountId) -> Option<T::PublicKey> {
        Relayers::<T>::get(who)
    }
    
    /// Verify a relayer's signature
    pub fn verify_relayer_signature(
        relayer: &T::AccountId, 
        payload: &[u8], 
        signature: &T::Signature
    ) -> bool {
        if let Some(public_key) = Self::get_relayer_public_key(relayer) {
            // Convert the public key to an account ID before verifying
            let account_id = public_key.into_account();
            signature.verify(payload, &account_id)
        } else {
            false
        }
    }

    pub fn address_is_active_validator(account_id: &T::AccountId) -> bool {
        <pallet_session::Pallet<T>>::validators().contains(account_id)
    }

    /// Convert Vec<u8> to BoundedVec
    pub fn to_bounded_vec<S: Get<u32>>(data: Vec<u8>) -> Result<BoundedVec<u8, S>, Error<T>> {
        BoundedVec::<u8, S>::try_from(data).map_err(|_| Error::<T>::DataTooLarge)
    }
    
    /// Get events for a specific chain and contract
    pub fn get_events_for_contract(
        chain_id: Vec<u8>,
        contract_address: Vec<u8>,
        limit: u32,
    ) -> Result<Vec<ChainEvent<T>>, Error<T>> {
        // Convert data to BoundedVec
        let chain_id_bounded = Self::to_bounded_vec::<T::MaxDataSize>(chain_id)?;
        let contract_address_bounded = Self::to_bounded_vec::<T::MaxDataSize>(contract_address)?;
        
        // Get event hashes
        let event_hashes = EventsByContract::<T>::get(&chain_id_bounded, &contract_address_bounded);
        
        // Collect events
        let mut events = Vec::new();
        for hash in event_hashes.iter().take(limit as usize) {
            if let Some(event) = ChainEvents::<T>::get(hash) {
                events.push(event);
            }
        }
        
        Ok(events)
    }
    
    /// List all registered relayers
    pub fn list_all_relayers() -> Vec<(T::AccountId, T::PublicKey)> {
        Relayers::<T>::iter().collect()
    }
}

impl<T: Config> Clone for ChainEvent<T> {
    fn clone(&self) -> Self {
        ChainEvent {
            chain_id: self.chain_id.clone(),
            block_number: self.block_number,
            contract_address: self.contract_address.clone(),
            event_data: self.event_data.clone(),
            timestamp: self.timestamp,
            verifications: self.verifications,
            verifiers: self.verifiers.clone(),
        }
    }
}

// Define weights for calls
pub trait WeightInfo {
    fn register_relayer() -> Weight;
    fn submit_event() -> Weight;
    fn verify_event() -> Weight;
    fn remove_relayer() -> Weight;
    fn validate_events() -> Weight;
    fn process_era_end() -> Weight;
}

impl WeightInfo for () {
    fn register_relayer() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    
    fn submit_event() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    
    fn verify_event() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    
    fn remove_relayer() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn validate_events() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn process_era_end() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

pub use pallet::*;
pub use pallet::Error;