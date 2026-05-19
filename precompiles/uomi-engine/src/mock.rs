use crate::{UomiEnginePrecompile, UomiEnginePrecompileCall};
use core::marker::PhantomData;
use fp_evm::{IsPrecompileResult, Precompile, PrecompileHandle};
use frame_election_provider_support::{
    bounds::{ElectionBounds, ElectionBoundsBuilder},
    onchain, SequentialPhragmen,
};
use frame_support::{
    construct_runtime, derive_impl, parameter_types,
    traits::{ConstU16, ConstU32, ConstU64, EstimateNextSessionRotation, Nothing},
    weights::Weight,
};
use frame_system::offchain::{
    AppCrypto, CreateBare, CreateSignedTransaction, CreateTransactionBase, SigningTypes,
};
use pallet_evm::{
    AddressMapping, EnsureAddressNever, EnsureAddressRoot, PrecompileResult, PrecompileSet,
};
use pallet_ipfs::{
    types::{Cid, ExpirationBlockNumber, UsableFromBlockNumber},
};
use pallet_session::{SessionHandler, ShouldEndSession};
use pallet_staking::TestBenchmarkingConfig;
use sp_core::{sr25519, ConstBool, Get, H160, H256, U256};
use sp_runtime::{
    curve::PiecewiseLinear,
    generic::UncheckedExtrinsic,
    testing::{TestXt, UintAuthorityId},
    traits::{BlakeTwo256, Convert, ConvertInto, IdentityLookup},
    BuildStorage, DispatchError, KeyTypeId, Perbill, Permill, RuntimeAppPublic,
};
use sp_staking::currency_to_vote::SaturatingCurrencyToVote;

pub type AccountId = sr25519::Public;
pub type Balance = u128;
pub type Block = frame_system::mocking::MockBlock<TestRuntime>;
pub type Extrinsic = TestXt<RuntimeCall, ()>;
pub type PrecompileCall = UomiEnginePrecompileCall<TestRuntime>;

pub const PRECOMPILE_ADDRESS: H160 = H160::repeat_byte(0xEE);
pub const AGENT_CONTRACT: H160 = H160(hex_literal::hex!(
    "Db8434F12f21a678F749cb34E6CE0c168776461c"
));
pub const USER: H160 = H160::repeat_byte(0xAA);

construct_runtime!(
    pub enum TestRuntime {
        System: frame_system,
        Balances: pallet_balances,
        Evm: pallet_evm,
        Timestamp: pallet_timestamp,
        Staking: pallet_staking,
        Session: pallet_session,
        Babe: pallet_babe,
        Ipfs: pallet_ipfs,
        Offences: pallet_offences,
        Historical: pallet_session::historical,
        TestingPallet: pallet_uomi_engine,
    }
);

#[derive(Debug, Clone, Copy)]
pub struct TestPrecompileSet<R>(PhantomData<R>);

impl<R> PrecompileSet for TestPrecompileSet<R>
where
    R: pallet_evm::Config + pallet_uomi_engine::Config,
    R::AddressMapping: AddressMapping<R::AccountId>,
    UomiEnginePrecompile<R>: Precompile,
{
    fn execute(&self, handle: &mut impl PrecompileHandle) -> Option<PrecompileResult> {
        match handle.code_address() {
            a if a == PRECOMPILE_ADDRESS => Some(UomiEnginePrecompile::<R>::execute(handle)),
            _ => None,
        }
    }

    fn is_precompile(&self, address: H160, _gas: u64) -> IsPrecompileResult {
        IsPrecompileResult::Answer {
            is_precompile: address == PRECOMPILE_ADDRESS,
            extra_cost: 0,
        }
    }
}

pub struct AddressMapper;

impl AddressMapping<AccountId> for AddressMapper {
    fn into_account_id(address: H160) -> AccountId {
        let mut account_id = [0u8; 32];
        account_id[0..20].copy_from_slice(address.as_bytes());
        sr25519::Public::from_raw(account_id)
    }
}

parameter_types! {
    pub const EpochDuration: u64 = 10;
    pub const ExpectedBlockTime: u64 = 6_000;
    pub const IpfsTemporaryPinningCost: Balance = 10 * 10_000;
    pub const TestMaxOffchainConcurrent: u32 = 5;
    pub const ExistentialDeposit: Balance = 1;
    pub const MinimumPeriod: u64 = 5;
    pub const WeightPerGas: Weight = Weight::from_parts(1, 0);
    pub const PrecompilesValue: TestPrecompileSet<TestRuntime> = TestPrecompileSet(PhantomData);
    pub MaxActiveValidators: u32 = 1000;
}

pub struct IpfsWrapper;

impl pallet_uomi_engine::ipfs::IpfsInterface<TestRuntime> for IpfsWrapper {
    fn get_agent_cid(nft_id: U256) -> Result<Cid, DispatchError> {
        pallet_ipfs::Pallet::<TestRuntime>::get_agent_cid(nft_id)
    }

    fn get_cid_status(
        cid: &Cid,
    ) -> Result<(ExpirationBlockNumber, UsableFromBlockNumber), DispatchError> {
        pallet_ipfs::Pallet::<TestRuntime>::get_cid_status(cid)
    }

    fn get_file(cid: &Cid) -> Result<Vec<u8>, sp_runtime::offchain::http::Error> {
        pallet_ipfs::Pallet::<TestRuntime>::get_file(cid)
    }

    fn pin_file(
        origin: <TestRuntime as frame_system::Config>::RuntimeOrigin,
        cid: Cid,
        duration: u64,
    ) -> frame_support::pallet_prelude::DispatchResult {
        pallet_ipfs::Pallet::<TestRuntime>::pin_file(origin, cid, duration)
    }
}

pub struct TestIpfsUrl;

impl Get<&'static str> for TestIpfsUrl {
    fn get() -> &'static str {
        "http://127.0.0.1:5001/api/v0"
    }
}

pub struct MockTssInterface;

impl uomi_primitives::TssInterface<TestRuntime> for MockTssInterface {
    fn create_agent_wallet(
        _nft_id: U256,
        _threshold: u8,
    ) -> frame_support::pallet_prelude::DispatchResult {
        Ok(())
    }

    fn agent_wallet_exists(_nft_id: U256) -> bool {
        true
    }

    fn get_agent_wallet_address(_nft_id: U256) -> Option<H160> {
        None
    }
}

impl uomi_primitives::UomiEngineInterface<TestRuntime> for MockTssInterface {
    fn clear_blacklist_for_nft(_nft_id: U256) -> frame_support::pallet_prelude::DispatchResult {
        Ok(())
    }
}

impl pallet_babe::Config for TestRuntime {
    type EpochDuration = EpochDuration;
    type ExpectedBlockTime = ExpectedBlockTime;
    type EpochChangeTrigger = pallet_babe::ExternalTrigger;
    type DisabledValidators = ();
    type WeightInfo = ();
    type MaxAuthorities = ConstU32<10>;
    type EquivocationReportSystem = ();
    type KeyOwnerProof = sp_core::Void;
    type MaxNominators = ConstU32<10>;
}

parameter_types! {
    pub const OffendingValidatorsThreshold: Perbill = Perbill::from_percent(17);
    pub const RewardCurve: &'static PiecewiseLinear<'static> = &REWARD_CURVE;
    pub static ElectionsBounds: ElectionBounds = ElectionBoundsBuilder::default().build();
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

pub struct OnChainSeqPhragmen;

impl onchain::Config for OnChainSeqPhragmen {
    type System = TestRuntime;
    type Solver = SequentialPhragmen<AccountId, Perbill>;
    type DataProvider = Staking;
    type WeightInfo = ();
    type Bounds = ElectionsBounds;
    type Sort = ConstBool<true>;
    type MaxBackersPerWinner = ConstU32<{ u32::MAX }>;
    type MaxWinnersPerPage = MaxActiveValidators;
}

pub type VoterList = pallet_staking::UseNominatorsAndValidatorsMap<TestRuntime>;

impl pallet_staking::Config for TestRuntime {
    type NominationsQuota = pallet_staking::FixedNominationsQuota<16>;
    type Currency = Balances;
    type CurrencyBalance = Balance;
    type UnixTime = Timestamp;
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
    type OldCurrency = Balances;
    type RuntimeHoldReason = RuntimeHoldReason;
    type MaxValidatorSet = MaxActiveValidators;
    type Filter = Nothing;
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
        _queued_validators: &[(AId, T)],
    ) {
    }

    fn on_disabled(_validator_index: u32) {}
}

impl pallet_session::Config for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = AccountId;
    type ValidatorIdOf = ConvertInto;
    type ShouldEndSession = TestShouldEndSession;
    type NextSessionRotation = TestNextSessionRotation;
    type SessionManager = ();
    type SessionHandler = TestSessionHandler;
    type Keys = UintAuthorityId;
    type WeightInfo = ();
    type DisablingStrategy = ();
}

impl SigningTypes for TestRuntime {
    type Public = sr25519::Public;
    type Signature = sr25519::Signature;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for TestRuntime {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Nonce = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = Block;
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

impl<C> CreateTransactionBase<C> for TestRuntime
where
    RuntimeCall: From<C>,
{
    type Extrinsic = Extrinsic;
    type RuntimeCall = RuntimeCall;
}

impl<C> CreateBare<C> for TestRuntime
where
    RuntimeCall: From<C>,
{
    fn create_bare(call: Self::RuntimeCall) -> Self::Extrinsic {
        UncheckedExtrinsic::new_bare(call)
    }
}

impl<C> CreateSignedTransaction<C> for TestRuntime
where
    RuntimeCall: From<C>,
{
    fn create_signed_transaction<A: AppCrypto<Self::Public, Self::Signature>>(
        call: RuntimeCall,
        _public: Self::Public,
        _account: Self::AccountId,
        nonce: Self::Nonce,
    ) -> Option<Self::Extrinsic> {
        Some(UncheckedExtrinsic::new_signed(call, nonce, (), ()))
    }
}

pub struct IdentityOf;

impl Convert<AccountId, Option<AccountId>> for IdentityOf {
    fn convert(account: AccountId) -> Option<AccountId> {
        Some(account)
    }
}

impl pallet_session::historical::Config for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type FullIdentification = AccountId;
    type FullIdentificationOf = IdentityOf;
}

impl pallet_offences::Config for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type IdentificationTuple = pallet_session::historical::IdentificationTuple<Self>;
    type OnOffenceHandler = ();
}

impl pallet_authorship::Config for TestRuntime {
    type FindAuthor = pallet_session::FindAccountFromAuthorIndex<Self, Babe>;
    type EventHandler = ();
}

pub struct TestOffenceReporter;

impl<Reporter, Offender, Off: sp_staking::offence::Offence<Offender>>
    sp_staking::offence::ReportOffence<Reporter, Offender, Off> for TestOffenceReporter
{
    fn report_offence(
        _reporters: Vec<Reporter>,
        _offence: Off,
    ) -> Result<(), sp_staking::offence::OffenceError> {
        Ok(())
    }

    fn is_known_offence(_offenders: &[Offender], _time_slot: &Off::TimeSlot) -> bool {
        false
    }
}

impl pallet_ipfs::Config for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type IpfsApiUrl = TestIpfsUrl;
    type AuthorityId = pallet_ipfs::crypto::AuthId;
    type Currency = pallet_balances::Pallet<TestRuntime>;
    type BlockNumber = u64;
    type TemporaryPinningCost = IpfsTemporaryPinningCost;
    type TssInterface = MockTssInterface;
    type UomiEngineInterface = MockTssInterface;
}

impl pallet_uomi_engine::Config for TestRuntime {
    type UomiAuthorityId = pallet_uomi_engine::crypto::AuthId;
    type RuntimeEvent = RuntimeEvent;
    type Randomness = pallet_babe::ParentBlockRandomness<TestRuntime>;
    type IpfsPallet = IpfsWrapper;
    type Currency = Balances;
    type MaxOffchainConcurrent = TestMaxOffchainConcurrent;
    type OffenceReporter = TestOffenceReporter;
}

impl pallet_timestamp::Config for TestRuntime {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

impl pallet_balances::Config for TestRuntime {
    type MaxLocks = ConstU32<50>;
    type MaxReserves = ConstU32<50>;
    type ReserveIdentifier = [u8; 8];
    type Balance = Balance;
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = ();
    type DoneSlashHandler = ();
}

impl pallet_evm::Config for TestRuntime {
    type FeeCalculator = ();
    type GasWeightMapping = pallet_evm::FixedGasWeightMapping<Self>;
    type WeightPerGas = WeightPerGas;
    type CallOrigin = EnsureAddressRoot<AccountId>;
    type CreateOriginFilter = ();
    type CreateInnerOriginFilter = ();
    type WithdrawOrigin = EnsureAddressNever<AccountId>;
    type AddressMapping = AddressMapper;
    type Currency = Balances;
    type Runner = pallet_evm::runner::stack::Runner<Self>;
    type PrecompilesType = TestPrecompileSet<Self>;
    type PrecompilesValue = PrecompilesValue;
    type Timestamp = Timestamp;
    type ChainId = ();
    type OnChargeTransaction = ();
    type BlockGasLimit = ();
    type BlockHashMapping = pallet_evm::SubstrateBlockHashMapping<Self>;
    type OnCreate = ();
    type FindAuthor = ();
    type WeightInfo = ();
    type GasLimitPovSizeRatio = ConstU64<4>;
    type AccountProvider = pallet_evm::FrameSystemAccountProvider<Self>;
    type GasLimitStorageGrowthRatio = ConstU64<0>;
}

pub(crate) struct ExtBuilder;

impl Default for ExtBuilder {
    fn default() -> Self {
        Self
    }
}

impl ExtBuilder {
    pub(crate) fn build(self) -> sp_io::TestExternalities {
        let mut storage = frame_system::GenesisConfig::<TestRuntime>::default()
            .build_storage()
            .expect("Frame system builds valid default genesis config");

        pallet_balances::GenesisConfig::<TestRuntime> {
            balances: vec![],
            ..Default::default()
        }
        .assimilate_storage(&mut storage)
        .expect("Balances genesis config is valid");

        pallet_staking::GenesisConfig::<TestRuntime> {
            validator_count: 2,
            minimum_validator_count: 1,
            stakers: vec![],
            slash_reward_fraction: Perbill::from_percent(10),
            ..Default::default()
        }
        .assimilate_storage(&mut storage)
        .expect("Staking genesis config is valid");

        pallet_babe::GenesisConfig::<TestRuntime> {
            authorities: vec![],
            epoch_config: sp_consensus_babe::BabeEpochConfiguration {
                c: (1, 4),
                allowed_slots: sp_consensus_babe::AllowedSlots::PrimarySlots,
            },
            _config: PhantomData,
        }
        .assimilate_storage(&mut storage)
        .expect("Babe genesis config is valid");

        let mut ext = sp_io::TestExternalities::new(storage);
        ext.execute_with(|| System::set_block_number(1));
        ext
    }
}
