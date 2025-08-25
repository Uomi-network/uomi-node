use scale_info::prelude::string::String;

use frame_election_provider_support::{
    bounds::{ElectionBounds, ElectionBoundsBuilder},
    onchain, SequentialPhragmen,
};
// INCLUDES
use frame_support::{
    construct_runtime, derive_impl, dispatch::DispatchResult, parameter_types,
    traits::EstimateNextSessionRotation, weights::Weight,
};
use frame_system::offchain::{CreateSignedTransaction, SendTransactionTypes, SigningTypes};
use pallet_babe;
use pallet_ipfs::{
    self,
    types::{Cid, ExpirationBlockNumber, UsableFromBlockNumber},
};
use pallet_session::{SessionHandler, ShouldEndSession};
use pallet_offences;
// Simple converter for historical session full identification
use sp_runtime::traits::Convert;
use pallet_staking::TestBenchmarkingConfig;
use sp_core::{sr25519::{Public, Signature}, ConstU128, ConstU16, ConstU32, ConstU64, Get, H256, U256
};


use pallet_uomi_engine::Call as UomiCall;
use sp_runtime::{
    curve::PiecewiseLinear,
    testing::{TestXt, UintAuthorityId},
    traits::{BlakeTwo256, IdentityLookup},
    BuildStorage, DispatchError, KeyTypeId, Perbill, Permill, RuntimeAppPublic,
};
use sp_staking::currency_to_vote::SaturatingCurrencyToVote;

use crate::{types::{MaxNumberOfShares, MinimumValidatorThreshold, PublicKey}, SignatureVerification};

// TYPES
pub type Balance = u128; // needed in System
pub type AccountId = Public;
pub type VoterList = pallet_staking::UseNominatorsAndValidatorsMap<Test>;
pub struct TestShouldEndSession;
impl ShouldEndSession<u64> for TestShouldEndSession {
    fn should_end_session(_now: u64) -> bool {
        false
    }
}
pub struct TestNextSessionRotation;

impl EstimateNextSessionRotation<u64> for TestNextSessionRotation {
    fn average_session_length() -> u64 {
        10
    }

    fn estimate_current_session_progress(_now: u64) -> (Option<Permill>, Weight) {
        (None, Weight::zero())
    }

    fn estimate_next_session_rotation(_now: u64) -> (Option<u64>, Weight) {
        (None, Weight::zero())
    }
}

pub struct TestSessionHandler;
impl<AId> SessionHandler<AId> for TestSessionHandler {
    const KEY_TYPE_IDS: &'static [KeyTypeId] = &[UintAuthorityId::ID];
    fn on_genesis_session<T>(_validators: &[(AId, T)]) {}
    fn on_new_session<T>(
        _changed: bool,
        _validators: &[(AId, T)],
        _queued_validators: &[(AId, T)],
    ) {
    }
    fn on_disabled(_validator_index: u32) {}
}

// RUNTIME
construct_runtime!(
    pub enum Test {
        System: frame_system,
        TestingPallet: crate,
        Staking: pallet_staking,
        Session: pallet_session,
        Balances: pallet_balances,
        Timestamp: pallet_timestamp,
        Ipfs: pallet_ipfs,
        Uomi: pallet_uomi_engine,
    Offences: pallet_offences,
    Historical: pallet_session::historical,
    }
);

impl pallet_session::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = AccountId;
    type ValidatorIdOf = pallet_staking::StashOf<Self>;
    type ShouldEndSession = TestShouldEndSession;
    type NextSessionRotation = TestNextSessionRotation;
    type SessionManager = ();
    type SessionHandler = TestSessionHandler;
    type Keys = UintAuthorityId;
    type WeightInfo = ();
}

// Provide an identity converter (AccountId -> Option<AccountId>) for historical session pallet
pub struct IdentityOf;
impl Convert<AccountId, Option<AccountId>> for IdentityOf {
    fn convert(a: AccountId) -> Option<AccountId> { Some(a) }
}

impl pallet_session::historical::Config for Test {
    type FullIdentification = AccountId; // minimal
    type FullIdentificationOf = IdentityOf; // simple identity mapping
}

impl pallet_offences::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type IdentificationTuple = pallet_session::historical::IdentificationTuple<Self>;
    type OnOffenceHandler = (); // no-op in tests
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Nonce = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = Public;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = frame_system::mocking::MockBlock<Test>;
    type RuntimeEvent = RuntimeEvent;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
}

impl SendTransactionTypes<UomiCall<Test>> for Test {
    type Extrinsic = sp_runtime::testing::TestXt<UomiCall<Test>, (u64, ())>;
    type OverarchingCall = UomiCall<Test>;
}

impl CreateSignedTransaction<UomiCall<Test>> for Test {
    fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
        call: UomiCall<Test>,
        _public: Self::Public,
        _account: <Test as frame_system::Config>::AccountId,
        nonce: <Test as frame_system::Config>::Nonce,
    ) -> Option<(UomiCall<Test>, (u64, (u64, ())))> {
        Some((call, (nonce, (nonce, ()))))
    }
}

pub struct MockVerifier {}
impl SignatureVerification<PublicKey> for MockVerifier {
    fn verify(_key: &PublicKey, _message: &[u8], sig: &crate::types::Signature) -> bool {
        sig[0] != 0
    }

}

impl crate::pallet::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxNumberOfShares = MaxNumberOfShares;
    type SignatureVerifier = MockVerifier;

    type AuthorityId = crate::crypto::AuthId;
    type MinimumValidatorThreshold = MinimumValidatorThreshold;
    type OffenceReporter = TestOffenceReporter;
}

pub struct TestOffenceReporter;
impl<Reporter, Offender, Off: sp_staking::offence::Offence<Offender>> sp_staking::offence::ReportOffence<Reporter, Offender, Off> for TestOffenceReporter {
    fn report_offence(_reporters: Vec<Reporter>, _offence: Off) -> Result<(), sp_staking::offence::OffenceError> { Ok(()) }
    fn is_known_offence(_offenders: &[Offender], _time_slot: &Off::TimeSlot) -> bool { false }
}

impl CreateSignedTransaction<crate::pallet::Call<Test>> for Test {
    fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
        call: Self::OverarchingCall,
        _public: Self::Public,
        _account: Self::AccountId,
        nonce: Self::Nonce,
    ) -> Option<(
        Self::OverarchingCall,
        <Self::Extrinsic as sp_runtime::traits::Extrinsic>::SignaturePayload,
    )> {
        Some((call, (nonce, (nonce, ()))))
    }
}
impl SendTransactionTypes<crate::pallet::Call<Test>> for Test {
    type Extrinsic = TestXt<crate::Call<Test>, (u64, ())>;
    type OverarchingCall = crate::Call<Test>;
}

impl pallet_uomi_engine::Config for Test {
    type UomiAuthorityId = pallet_uomi_engine::crypto::AuthId;
    type RuntimeEvent = RuntimeEvent;
    type Randomness = pallet_babe::ParentBlockRandomness<Test>;
    type IpfsPallet = IpfsWrapper;
    type InherentDataType = ();
}

pub struct IpfsWrapper;

impl pallet_uomi_engine::ipfs::IpfsInterface<Test> for IpfsWrapper {
    fn get_agent_cid(nft_id: U256) -> Result<Cid, DispatchError> {
        pallet_ipfs::Pallet::<Test>::get_agent_cid(nft_id)
    }

    fn get_cid_status(
        cid: &Cid,
    ) -> Result<(ExpirationBlockNumber, UsableFromBlockNumber), DispatchError> {
        pallet_ipfs::Pallet::<Test>::get_cid_status(cid)
    }

    fn get_file(cid: &Cid) -> Result<Vec<u8>, sp_runtime::offchain::http::Error> {
        pallet_ipfs::Pallet::<Test>::get_file(cid)
    }

    fn pin_file(
        origin: <Test as frame_system::Config>::RuntimeOrigin,
        cid: Cid,
        duration: u64,
    ) -> DispatchResult {
        pallet_ipfs::Pallet::<Test>::pin_file(origin, cid, duration)
    }
}

// First, create a custom type for the test IPFS URL
pub struct TestIpfsUrl;

// Implement the trait that your config expects for IpfsApiUrl
impl Get<&'static str> for TestIpfsUrl {
    fn get() -> &'static str {
        // You can return a fixed URL for testing
        &"http://127.0.0.1:5001/api/v0"
    }
}

impl pallet_ipfs::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type IpfsApiUrl = TestIpfsUrl;
    type AuthorityId = pallet_ipfs::crypto::AuthId;
    type Currency = pallet_balances::Pallet<Test>;
    type BlockNumber = u64;
    type TemporaryPinningCost = IpfsTemporaryPinningCost;
    type TssInterface = crate::Pallet<Test>;
}

impl pallet_babe::Config for Test {
    type EpochDuration = EpochDuration;
    type ExpectedBlockTime = ExpectedBlockTime;
    type EpochChangeTrigger = pallet_babe::ExternalTrigger;
    type DisabledValidators = ();
    type WeightInfo = ();
    type MaxAuthorities = ConstU32<10>;
    // Rimuovi KeyOwnerProof, KeyOwnerProofSystem, KeyOwnerIdentification
    type EquivocationReportSystem = (); // Aggiungi questa riga
    type KeyOwnerProof = sp_core::Void; // Aggiungi questa riga
    type MaxNominators = ConstU32<10>; // Aggiungi questa riga
}

impl SigningTypes for Test {
    type Public = Public;
    type Signature = Signature;
}

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = ConstU64<5>;
    type WeightInfo = ();
}

pallet_staking_reward_curve::build! {
   const REWARD_CURVE: PiecewiseLinear<'static> = curve!(
       min_inflation: 0_025_000,
       max_inflation: 0_100_000,
       ideal_stake: 0_500_000,
       falloff: 0_050_000,
       max_piece_count: 40,
       test_precision: 0_005_000,
   );
}
parameter_types! {
    pub const EpochDuration: u64 = 10;
    pub const IpfsApiUrl: &'static str = "http://localhost:5001/api/v0";
    pub const IpfsTemporaryPinningCost: Balance = 10 * 10000;
    pub const ExpectedBlockTime: u64 = 6_000;
    pub const OffendingValidatorsThreshold: Perbill = Perbill::from_percent(17);
    pub static ElectionsBounds: ElectionBounds = ElectionBoundsBuilder::default().build();
    pub const RewardCurve: &'static PiecewiseLinear<'static> = &REWARD_CURVE;
}

impl SendTransactionTypes<pallet_ipfs::Call<Test>> for Test {
    type Extrinsic = sp_runtime::testing::TestXt<pallet_ipfs::Call<Test>, (u64, ())>;
    type OverarchingCall = pallet_ipfs::Call<Test>;
}

impl CreateSignedTransaction<pallet_ipfs::Call<Test>> for Test {
    fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
        call: pallet_ipfs::Call<Test>,
        _public: Self::Public,
        _account: <Test as frame_system::Config>::AccountId,
        nonce: <Test as frame_system::Config>::Nonce,
    ) -> Option<(pallet_ipfs::Call<Test>, (u64, (u64, ())))> {
        Some((call, (nonce, (nonce, ()))))
    }
}

pub struct OnChainSeqPhragmen;
impl onchain::Config for OnChainSeqPhragmen {
    type System = Test;
    type Solver = SequentialPhragmen<AccountId, Perbill>;
    type DataProvider = Staking;
    type WeightInfo = ();
    type MaxWinners = ConstU32<100>;
    type Bounds = ElectionsBounds;
}

impl pallet_staking::Config for Test {
    type NominationsQuota = pallet_staking::FixedNominationsQuota<16>;
    type Currency = Balances;
    type CurrencyBalance = Balance;
    type UnixTime = Timestamp;
    type OffendingValidatorsThreshold = OffendingValidatorsThreshold;
    type CurrencyToVote = SaturatingCurrencyToVote;
    type ElectionProvider = onchain::OnChainExecution<OnChainSeqPhragmen>;
    type GenesisElectionProvider = Self::ElectionProvider;
    type HistoryDepth = ConstU32<84>;
    type RewardRemainder = ();
    type RuntimeEvent = RuntimeEvent;
    type Slash = ();
    type Reward = ();
    type SessionsPerEra = ConstU32<6>;
    type BondingDuration = ConstU32<28>;
    type SlashDeferDuration = ConstU32<27>;
    type AdminOrigin = frame_system::EnsureRoot<AccountId>;
    type SessionInterface = ();
    type EraPayout = pallet_staking::ConvertCurve<RewardCurve>;
    type NextNewSession = Session;
    type MaxExposurePageSize = ConstU32<64>;
    type VoterList = VoterList;
    type TargetList = pallet_staking::UseValidatorsMap<Self>;
    type MaxUnlockingChunks = ConstU32<32>;
    type MaxControllersInDeprecationBatch = ConstU32<256>;
    type EventListeners = ();
    type BenchmarkingConfig = TestBenchmarkingConfig;
    type WeightInfo = ();
}

impl pallet_balances::Config for Test {
    type MaxLocks = ConstU32<50>;
    type MaxReserves = ConstU32<50>;
    type ReserveIdentifier = [u8; 8];
    type Balance = Balance;
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ConstU128<1>;
    type AccountStore = System;
    type WeightInfo = ();
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type RuntimeHoldReason = ();
    type RuntimeFreezeReason = ();
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    pallet_balances::GenesisConfig::<Test> { balances: vec![] }
        .assimilate_storage(&mut t)
        .unwrap();

    pallet_staking::GenesisConfig::<Test> {
        validator_count: 2,
        minimum_validator_count: 1,
        stakers: vec![],
        slash_reward_fraction: Perbill::from_percent(10),
        ..Default::default()
    }
    .assimilate_storage(&mut t)
    .unwrap();



    t.into()
}
