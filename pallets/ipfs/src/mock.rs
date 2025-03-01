use frame_election_provider_support::{
    bounds::{ ElectionBounds, ElectionBoundsBuilder },
    onchain,
    SequentialPhragmen,
};
// INCLUDES
use frame_support::{
    construct_runtime,
    derive_impl,
    parameter_types,
    traits::EstimateNextSessionRotation,
    weights::Weight,
};
use frame_system::offchain::{
    AppCrypto,
    CreateSignedTransaction,
    SendTransactionTypes,
    SigningTypes,
};
use pallet_session::{ SessionHandler, ShouldEndSession };
use pallet_staking::TestBenchmarkingConfig;
use sp_core::{ sr25519::{ Public, Signature }, ConstU16, ConstU32, ConstU64, Get, H256, ConstU128 };

use sp_runtime::{
    curve::PiecewiseLinear,
    testing::{ TestXt, UintAuthorityId },
    traits::{ BlakeTwo256, IdentityLookup },
    BuildStorage,
    KeyTypeId,
    Perbill,
    Permill,
    RuntimeAppPublic,
};
use sp_staking::currency_to_vote::SaturatingCurrencyToVote;

// TYPES
pub type BlockNumber = u64;
pub type Balance = u128; // needed in System
pub type AccountId = Public;
pub type VoterList = pallet_staking::UseNominatorsAndValidatorsMap<Test>;
pub struct OnChainSeqPhragmen;
pub struct TestShouldEndSession;
pub struct TestNextSessionRotation;
pub struct TestSessionHandler;

// RUNTIME
construct_runtime!(
    pub enum Test {
        System: frame_system,
        TestingPallet: crate,
        Staking: pallet_staking,
        Balances: pallet_balances,
        Session: pallet_session,
        Timestamp: pallet_timestamp,
    }
);

parameter_types! {
    pub const IpfsPinningCost: Balance = 100;

    pub const BondingDuration: u32 = 28;
    pub const MaxNominatorRewardedPerValidator: u32 = 64;
    pub const MaxNominators: u32 = 1000;
    pub const OffendingValidatorsThreshold: Perbill = Perbill::from_percent(17);
    pub const VoterListMaxSize: u32 = 1000;
    pub const MaxControllersInDeprecationBatch: u32 = 256;
    pub const RewardCurve: &'static PiecewiseLinear<'static> = &REWARD_CURVE;
    pub static ElectionsBounds: ElectionBounds = ElectionBoundsBuilder::default().build();
    pub const MaxValidationDataLength: u32 = 1024;
}

pallet_staking_reward_curve::build! {
    const REWARD_CURVE: PiecewiseLinear<'static> =
        curve!(
       min_inflation: 0_025_000,
       max_inflation: 0_100_000,
       ideal_stake: 0_500_000,
       falloff: 0_050_000,
       max_piece_count: 40,
       test_precision: 0_005_000,
   );
}

// CONFIG TRAIT IMPLS
// SYSTEM
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

// IPFS

// First, create a custom type for the test IPFS URL
pub struct TestIpfsUrl;

// Implement the trait that your config expects for IpfsApiUrl
impl Get<&'static str> for TestIpfsUrl {
    fn get() -> &'static str {
        // You can return a fixed URL for testing
        &"http://127.0.0.1:5001/api/v0"
    }
}
impl crate::Config for Test {
    type RuntimeEvent = RuntimeEvent;

    type IpfsApiUrl = TestIpfsUrl;
    type AuthorityId = crate::crypto::AuthId;
    type Currency = pallet_balances::Pallet<Test>;
    type BlockNumber = BlockNumber;
    type TemporaryPinningCost = IpfsPinningCost;
}

// SIGNING TYPES
impl SigningTypes for Test {
    type Public = Public;
    type Signature = Signature;
}

// STAKING
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

// REQUIRED BY type ElectionProvider = onchain::OnChainExecution<OnChainSeqPhragmen>;
impl onchain::Config for OnChainSeqPhragmen {
    type System = Test;
    type Solver = SequentialPhragmen<AccountId, Perbill>;
    type DataProvider = Staking;
    type WeightInfo = ();
    type MaxWinners = ConstU32<100>;
    type Bounds = ElectionsBounds;
}

// CREATE SIGNED TRANSACTION
impl SendTransactionTypes<crate::Call<Test>> for Test {
    type Extrinsic = TestXt<crate::Call<Test>, (u64, ())>;
    type OverarchingCall = crate::Call<Test>;
}

impl CreateSignedTransaction<crate::Call<Test>> for Test {
    fn create_transaction<C: AppCrypto<Self::Public, Self::Signature>>(
        call: crate::Call<Test>,
        _public: Self::Public,
        _account: <Test as frame_system::Config>::AccountId,
        nonce: <Test as frame_system::Config>::Nonce
    ) -> Option<(crate::Call<Test>, (u64, (u64, ())))> {
        Some((call, (nonce, (nonce, ()))))
    }
}

// BALANCES
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
// SESSION
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

impl EstimateNextSessionRotation<BlockNumber> for TestNextSessionRotation {
    fn average_session_length() -> BlockNumber {
        10
    }

    fn estimate_current_session_progress(_now: BlockNumber) -> (Option<Permill>, Weight) {
        (None, Weight::zero())
    }

    fn estimate_next_session_rotation(_now: BlockNumber) -> (Option<BlockNumber>, Weight) {
        (None, Weight::zero())
    }
}

impl ShouldEndSession<BlockNumber> for TestShouldEndSession {
    fn should_end_session(_now: BlockNumber) -> bool {
        false
    }
}

impl<AId> SessionHandler<AId> for TestSessionHandler {
    const KEY_TYPE_IDS: &'static [KeyTypeId] = &[UintAuthorityId::ID];
    fn on_genesis_session<T>(_validators: &[(AId, T)]) {}
    fn on_new_session<T>(
        _changed: bool,
        _validators: &[(AId, T)],
        _queued_validators: &[(AId, T)]
    ) {}
    fn on_disabled(_validator_index: u32) {}
}
// TIMESTAMP
impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = ConstU64<5>;
    type WeightInfo = ();
}

// Create test externalities
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();

    (pallet_balances::GenesisConfig::<Test> { balances: vec![] })
        .assimilate_storage(&mut t)
        .unwrap();

    (pallet_staking::GenesisConfig::<Test> {
        validator_count: 2,
        minimum_validator_count: 1,
        stakers: vec![],
        slash_reward_fraction: Perbill::from_percent(10),
        ..Default::default()
    })
        .assimilate_storage(&mut t)
        .unwrap();

    t.into()
}
