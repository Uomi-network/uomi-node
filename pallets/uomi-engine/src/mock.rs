use core::marker::PhantomData;
use frame_election_provider_support::{
    self,
    bounds::{ElectionBounds, ElectionBoundsBuilder},
    onchain,
    SequentialPhragmen,
};
use frame_support::{
    derive_impl,
    inherent::{InherentData, InherentIdentifier, ProvideInherent},
    parameter_types,
    traits::{ConstU16, ConstU32, ConstU64, EstimateNextSessionRotation},
    weights::Weight,
};
use frame_system::offchain::{CreateSignedTransaction, SigningTypes};
use pallet_ipfs::{
    self,
    types::{Cid, ExpirationBlockNumber, UsableFromBlockNumber},
};
use pallet_session::{SessionHandler, ShouldEndSession};
use pallet_staking::TestBenchmarkingConfig;
use sp_core::{
    sr25519::{Public, Signature},
    ConstU128,
    Get,
    H256,
    U256,
};
use sp_runtime::{
    curve::PiecewiseLinear,
    traits::{BlakeTwo256, IdentityLookup},
    testing::UintAuthorityId,
    BuildStorage,
    DispatchError,
    KeyTypeId,
    Perbill,
    Permill,
    RuntimeAppPublic,
};
use sp_staking::currency_to_vote::SaturatingCurrencyToVote;
use sp_std::collections::btree_map::BTreeMap;

// Local imports
use crate::{
    types::{AiModelKey, BlockNumber, Data, RequestId}, Call, DispatchResult, InherentError, OpocLevel
};
use crate as pallet_uomi_engine;
use pallet_uomi_engine::Call as UomiCall;

type Balance = u128;
type AccountId = Public;

frame_support::construct_runtime!(
   pub enum Test {
       System: frame_system,
       Balances: pallet_balances,
       TestingPallet: pallet_uomi_engine,
       Timestamp: pallet_timestamp,
       Staking: pallet_staking,
       Session: pallet_session,
    Babe: pallet_babe,
    Ipfs: pallet_ipfs,
    Offences: pallet_offences,
    Historical: pallet_session::historical,
   }
);

parameter_types! {
    pub const EpochDuration: u64 = 10;
    pub const IpfsApiUrl: &'static str = "http://localhost:5001/api/v0";
    pub const IpfsTemporaryPinningCost: Balance = 10 * 10000;
    pub const ExpectedBlockTime: u64 = 6_000;
    pub const TestMaxOffchainConcurrent: u32 = 5; // NOTE: This config is not used anymore, but kept for retro-compatibility.
}

pub struct IpfsWrapper;

impl pallet_uomi_engine::ipfs::IpfsInterface<Test> for IpfsWrapper {
    fn get_agent_cid(nft_id: U256) -> Result<Cid, DispatchError> {
        pallet_ipfs::Pallet::<Test>::get_agent_cid(nft_id)
    }

    fn get_cid_status(cid: &Cid) -> Result<(ExpirationBlockNumber, UsableFromBlockNumber), DispatchError> {
        pallet_ipfs::Pallet::<Test>::get_cid_status(cid)
    }

    fn get_file(cid: &Cid) -> Result<Vec<u8>, sp_runtime::offchain::http::Error> {
        pallet_ipfs::Pallet::<Test>::get_file(cid)
    }

    fn pin_file(
        origin: <Test as frame_system::Config>::RuntimeOrigin,
        cid: Cid, 
        duration: u64
    ) -> DispatchResult {
        pallet_ipfs::Pallet::<Test>::pin_file(origin, cid, duration)
    }
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
    type KeyOwnerProof = sp_core::Void;  // Aggiungi questa riga
    type MaxNominators = ConstU32<10>;    // Aggiungi questa riga
}

parameter_types! {
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

pub struct OnChainSeqPhragmen;
impl onchain::Config for OnChainSeqPhragmen {
	type System = Test;
	type Solver = SequentialPhragmen<AccountId, Perbill>;
	type DataProvider = Staking;
	type WeightInfo = ();
	type MaxWinners = ConstU32<100>;
	type Bounds = ElectionsBounds;
}

impl MockInherentDataProvider {
    fn opoc_run() -> Result<(
        BTreeMap<AccountId, bool>,
        BTreeMap<(RequestId, AccountId), (BlockNumber, OpocLevel)>,
        BTreeMap<AccountId, BTreeMap<RequestId, bool>>,
        BTreeMap<RequestId, BTreeMap<AccountId, bool>>,
        BTreeMap<RequestId, BTreeMap<AccountId, bool>>,
        BTreeMap<RequestId, (Data, u32, u32, U256)>
    ), DispatchError> {
        Ok((
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        ))
    }

    pub fn aimodelscalc_run() ->  BTreeMap<AiModelKey, (Data, Data, BlockNumber)> {
        BTreeMap::new()
    }
}

pub struct MockInherentDataProvider;

impl ProvideInherent for MockInherentDataProvider {
    type Call = Call<Test>;
    type Error = InherentError;
    const INHERENT_IDENTIFIER: InherentIdentifier = pallet_uomi_engine::consts::PALLET_INHERENT_IDENTIFIER;

    fn create_inherent(_data: &InherentData) -> Option<Self::Call> {
        Some(Call::set_inherent_data { 
            opoc_operations: (BTreeMap::new(), BTreeMap::new(), BTreeMap::new(), BTreeMap::new(), BTreeMap::new(), BTreeMap::new()),
            aimodelscalc_operations: BTreeMap::new(),
        })
    }

    fn check_inherent(
        _call: &Self::Call,
        _data: &InherentData,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn is_inherent(call: &Self::Call) -> bool {
        matches!(call, Call::set_inherent_data { .. })
    }
}

pub type VoterList = pallet_staking::UseNominatorsAndValidatorsMap<Test>;

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
       _queued_validators: &[(AId, T)]
   ) {}
   fn on_disabled(_validator_index: u32) {}
}

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

impl SigningTypes for Test {
   type Public = Public;
   type Signature = Signature;
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

impl CreateSignedTransaction<UomiCall<Test>> for Test {
   fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
       call: UomiCall<Test>,
       _public: Self::Public,
       _account: <Test as frame_system::Config>::AccountId,
       nonce: <Test as frame_system::Config>::Nonce
   ) -> Option<(UomiCall<Test>, (u64, (u64, ())))> {
       Some((call, (nonce, (nonce, ()))))
   }
}


impl CreateSignedTransaction<pallet_ipfs::Call<Test>> for Test {
    fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
        call: pallet_ipfs::Call<Test>,
        _public: Self::Public,
        _account: <Test as frame_system::Config>::AccountId,
        nonce: <Test as frame_system::Config>::Nonce
    ) -> Option<(pallet_ipfs::Call<Test>, (u64, (u64, ())))> {
        Some((call, (nonce, (nonce, ()))))
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

// Mock implementation for TssInterface to satisfy pallet_ipfs Config in this test runtime
pub struct MockTssInterface;

impl uomi_primitives::TssInterface<Test> for MockTssInterface {
    fn create_agent_wallet(_nft_id: sp_core::U256, _threshold: u8) -> frame_support::pallet_prelude::DispatchResult {
        Ok(())
    }

    fn agent_wallet_exists(_nft_id: sp_core::U256) -> bool {
        true
    }

    fn get_agent_wallet_address(_nft_id: sp_core::U256) -> Option<sp_core::H160> {
        None
    }
}
impl pallet_ipfs::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type IpfsApiUrl = TestIpfsUrl;
    type AuthorityId = pallet_ipfs::crypto::AuthId;
    type Currency = pallet_balances::Pallet<Test>;
    type BlockNumber = u64;
    type TemporaryPinningCost = IpfsTemporaryPinningCost;
    type TssInterface = MockTssInterface;
}

impl pallet_uomi_engine::Config for Test {
    type UomiAuthorityId = pallet_uomi_engine::crypto::AuthId;
    type RuntimeEvent = RuntimeEvent;
    type Randomness = pallet_babe::ParentBlockRandomness<Test>;
    type IpfsPallet = IpfsWrapper;
    type InherentDataType = ();
    type MaxOffchainConcurrent = TestMaxOffchainConcurrent; // NOTE: This config is not used anymore, but kept for retro-compatibility.
    type OffenceReporter = TestOffenceReporter;
}

// Provide minimal implementations required by the pallet Config trait bounds.
// Provide an identity converter (AccountId -> Option<AccountId>) for historical session pallet
pub struct IdentityOf;
impl sp_runtime::traits::Convert<AccountId, Option<AccountId>> for IdentityOf {
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

impl pallet_authorship::Config for Test {
    type FindAuthor = pallet_session::FindAccountFromAuthorIndex<Self, Babe>;
    type EventHandler = ();
}

// Provide a minimal OffenceReporter for the mock runtime so the pallet's Config
// associated type is satisfied in tests.
pub struct TestOffenceReporter;
impl<Reporter, Offender, Off: sp_staking::offence::Offence<Offender>> sp_staking::offence::ReportOffence<Reporter, Offender, Off> for TestOffenceReporter {
    fn report_offence(_reporters: Vec<Reporter>, _offence: Off) -> Result<(), sp_staking::offence::OffenceError> { Ok(()) }
    fn is_known_offence(_offenders: &[Offender], _time_slot: &Off::TimeSlot) -> bool { false }
}

// Minimal authorship config to satisfy trait bounds in tests (no-op implementations)
// No authorship-specific behavior needed in tests; authorship is implemented in other test modules.

impl pallet_timestamp::Config for Test {
   type Moment = u64;
   type OnTimestampSet = ();
   type MinimumPeriod = ConstU64<5>;
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
    let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();

    pallet_balances::GenesisConfig::<Test> {
       balances: vec![],
    }
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

    pallet_babe::GenesisConfig::<Test> {
        authorities: vec![],
        epoch_config: sp_consensus_babe::BabeEpochConfiguration {
            c: (1, 4),
            allowed_slots: sp_consensus_babe::AllowedSlots::PrimarySlots,
        },
        _config: PhantomData,
    }
    .assimilate_storage(&mut t)
    .unwrap();

    t.into()
}