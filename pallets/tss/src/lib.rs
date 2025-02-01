use core::fmt::Debug;
use frame_support::pallet_prelude::*;
mod mock;
mod tests;
mod types;
mod dkground1;
mod dkground2;
mod dkground3;
mod dkghelpers;
mod signround1;
use scale_info::TypeInfo;
use types::{
    Key, MaxMessageSize, PublicKey,
    SessionId, Share, Signature,
};

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_system::ensure_signed;
    use frame_system::pallet_prelude::OriginFor;

    use super::*;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + TypeInfo {
        // Events emitted by the pallet.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        #[pallet::constant]
        type MaxNumberOfShares: Get<u32>;
    }

    #[derive(Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq, Clone, Copy)]
    pub enum SessionState {
        DKGInProgress,
        DKGComplete,
        SigningInProgress,
        Complete,
    }

    #[derive(Encode, Decode, MaxEncodedLen, Debug, PartialEq, Eq, Clone, TypeInfo)] // IMPORTANT: Keep these derives
    pub struct DKGSession<T>
    where
        T: Config,
    {
        pub participants: BoundedVec<T::AccountId, <T as Config>::MaxNumberOfShares>,
        pub threshold: u32,
        pub state: SessionState,
        pub public_key: Option<PublicKey>, // Corrected: PublicKey<T>
        pub signature_shares: BoundedVec<Share, <T as Config>::MaxNumberOfShares>, // Corrected: Share<T>
    }

    #[pallet::storage]
    #[pallet::getter(fn get_tss_key)]
    pub type TSSKey<T: Config> = StorageValue<_, Key, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn get_dkg_session)]
    pub type DkgSessions<T: Config> =
        StorageMap<_, Blake2_128Concat, SessionId, DKGSession<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn next_session_id)]
    pub type NextSessionId<T: Config> = StorageValue<_, SessionId, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new TSS key has been set.
        TSSKeyUpdated(Key),
    }

    #[pallet::error]
    pub enum Error<T> {
        KeyUpdateFailed,
        DuplicateParticipant,
        InvalidParticipantsCount,
        InvalidThreshold
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(10_000)]
        pub fn create_dkg_session(
            origin: OriginFor<T>,
            participants: Vec<T::AccountId>,
            threshold: u32,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            ensure!(threshold > 0, Error::<T>::InvalidThreshold);
            ensure!(participants.len() > 0, Error::<T>::InvalidParticipantsCount);
            ensure!(threshold < participants.len().try_into().unwrap(), Error::<T>::InvalidThreshold);

            // Check for duplicate participants
            let mut sorted_participants = participants.clone();
            sorted_participants.sort();
            for i in 1..sorted_participants.len() {
                if sorted_participants[i] == sorted_participants[i-1] {
                    return Err(Error::<T>::DuplicateParticipant.into());
                }
            }

            // Convert Vec to BoundedVec
            let participants =
                BoundedVec::try_from(participants).map_err(|_| Error::<T>::KeyUpdateFailed)?;

            // Create new DKG session
            let session = DKGSession {
                participants,
                threshold,
                state: SessionState::DKGInProgress,
                public_key: None,
                signature_shares: BoundedVec::default(),
            };

            // Generate random session ID
            let session_id = Self::get_next_session_id();

            // Store the session
            DkgSessions::<T>::insert(session_id, session);

            Ok(())
        }
    }
    impl<T: Config> Pallet<T> {
        pub fn get_next_session_id() -> SessionId {
            let session_id = Self::next_session_id();
            NextSessionId::<T>::put(session_id + 1);

            session_id
        }
    }
}
