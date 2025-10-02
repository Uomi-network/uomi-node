//! # Era Payout Events Pallet
//!
//! A minimal pallet for emitting events related to era payouts and agent rewards.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::{
        pallet_prelude::*,
        traits::Get,
    };
    use sp_core::H160;
    use sp_runtime::traits::Zero;
    use frame_system::pallet_prelude::BlockNumberFor;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        #[cfg(feature = "try-runtime")]
        fn try_state(_n: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
            // Nessun controllo specifico richiesto: pallet solo eventi.
            Ok(())
        }
    }

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        
        /// Balance type for the runtime
        type Balance: Parameter 
            + Default 
            + Copy 
            + From<u128> 
            + Into<u128>
            + Zero;
        
        /// Maximum size of CID/NFT ID
        type MaxCidSize: Get<u32>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Agent received a payout
        /// [nft_id, evm_address, substrate_account, amount]  
        AgentPayout {
            nft_id: BoundedVec<u8, T::MaxCidSize>,
            evm_address: H160,
            substrate_account: T::AccountId,
            amount: T::Balance,
        },
        
        /// Treasury received remainder from era payout
        /// [amount]
        TreasuryRemainder {
            amount: T::Balance,
        },
        
        /// Era payout distribution started
        /// [total_payout, agent_count, individual_share]
        PayoutDistributionStarted {
            total_payout: T::Balance,
            agent_count: u32,
            individual_share: T::Balance,
        },
        
        /// Failed to process agent payout
        /// [nft_id, reason]
        AgentPayoutFailed {
            nft_id: BoundedVec<u8, T::MaxCidSize>,
            reason: BoundedVec<u8, ConstU32<64>>,
        },
        
        /// Invalid public key for agent
        /// [session_id, key_length]
        InvalidAgentPublicKey {
            session_id: u64,
            key_length: u32,
        },
    }

    impl<T: Config> Pallet<T> {
        /// Emit an agent payout event
        pub fn emit_agent_payout(
            nft_id: BoundedVec<u8, T::MaxCidSize>,
            evm_address: H160,
            substrate_account: T::AccountId,
            amount: T::Balance,
        ) {
            Self::deposit_event(Event::AgentPayout {
                nft_id,
                evm_address,
                substrate_account,
                amount,
            });
        }

        /// Emit a treasury remainder event
        pub fn emit_treasury_remainder(amount: T::Balance) {
            Self::deposit_event(Event::TreasuryRemainder { amount });
        }

        /// Emit a payout distribution started event
        pub fn emit_payout_distribution_started(
            total_payout: T::Balance,
            agent_count: u32,
            individual_share: T::Balance,
        ) {
            Self::deposit_event(Event::PayoutDistributionStarted {
                total_payout,
                agent_count,
                individual_share,
            });
        }

        /// Emit an agent payout failed event
        pub fn emit_agent_payout_failed(nft_id: BoundedVec<u8, T::MaxCidSize>, reason: &str) {
            let bounded_reason = BoundedVec::try_from(reason.as_bytes().to_vec())
                .unwrap_or_default();
            Self::deposit_event(Event::AgentPayoutFailed {
                nft_id,
                reason: bounded_reason,
            });
        }

        /// Emit an invalid agent public key event
        pub fn emit_invalid_agent_public_key(session_id: u64, key_length: u32) {
            Self::deposit_event(Event::InvalidAgentPublicKey {
                session_id,
                key_length,
            });
        }
    }
}