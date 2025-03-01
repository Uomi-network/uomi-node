// This file is part of Uomi.

// Copyright (C) Uomi.
// SPDX-License-Identifier: GPL-3.0-or-later

// Uomi is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Uomi is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Uomi. If not, see <http://www.gnu.org/licenses/>.

use crate::AssetsExtension;
use frame_support::traits::{AsEnsureOriginWithArg, ConstU128, Currency, Randomness};
use frame_support::{
    parameter_types,
    traits::{ConstU32, ConstU64, Nothing},
    weights::Weight,
};
use frame_system::EnsureSigned;
use pallet_contracts::chain_extension::RegisteredChainExtension;
use pallet_contracts::{Config, DefaultAddressGenerator, Frame};
use sp_core::crypto::AccountId32;
use sp_runtime::{
    testing::H256,
    traits::{BlakeTwo256, Convert, IdentityLookup, Zero},
    BuildStorage, Perbill,
};

pub type BlockNumber = u32;
pub type Balance = u128;
pub type AssetId = u128;

type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

parameter_types! {
    pub const BlockHashCount: BlockNumber = 250;
    pub BlockWeights: frame_system::limits::BlockWeights =
        frame_system::limits::BlockWeights::simple_max(
            Weight::from_parts(2_000_000_000_000, u64::MAX),
        );
}
impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = BlockWeights;
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type Nonce = u32;
    type Block = Block;
    type Hash = H256;
    type RuntimeCall = RuntimeCall;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId32;
    type Lookup = IdentityLookup<Self::AccountId>;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = BlockHashCount;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ();
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<16>;
    type RuntimeTask = RuntimeTask;
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
}

parameter_types! {
    pub static UnstableInterface: bool = true;
    pub Schedule: pallet_contracts::Schedule<Test> = Default::default();
    pub static DepositPerByte: Balance = 1;
    pub const DepositPerItem: Balance = 1;
    pub const DefaultDepositLimit: Balance = 1;
    pub const MaxDelegateDependencies: u32 = 32;
    pub const CodeHashLockupDepositPercent: Perbill = Perbill::from_percent(1);
}

pub struct DummyDeprecatedRandomness;
impl Randomness<H256, BlockNumber> for DummyDeprecatedRandomness {
    fn random(_: &[u8]) -> (H256, BlockNumber) {
        (Default::default(), Zero::zero())
    }
}

impl pallet_contracts::Config for Test {
    type Time = Timestamp;
    type Randomness = DummyDeprecatedRandomness;
    type Currency = Balances;
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type CallFilter = Nothing;
    type CallStack = [Frame<Self>; 5];
    type WeightPrice = Self;
    type WeightInfo = ();
    type ChainExtension = AssetsExtension<Self>;
    type Schedule = Schedule;
    type DepositPerByte = DepositPerByte;
    type DepositPerItem = DepositPerItem;
    type DefaultDepositLimit = DefaultDepositLimit;
    type AddressGenerator = DefaultAddressGenerator;
    type MaxCodeLen = ConstU32<{ 123 * 1024 }>;
    type MaxStorageKeyLen = ConstU32<128>;
    type UnsafeUnstableInterface = UnstableInterface;
    type MaxDebugBufferLen = ConstU32<{ 2 * 1024 * 1024 }>;
    type CodeHashLockupDepositPercent = CodeHashLockupDepositPercent;
    type Debug = ();
    type Environment = ();
    type MaxDelegateDependencies = MaxDelegateDependencies;
    type Migrations = ();
    type RuntimeHoldReason = RuntimeHoldReason;
    type Xcm = ();
    type UploadOrigin = EnsureSigned<AccountId32>;
    type InstantiateOrigin = EnsureSigned<AccountId32>;
    type ApiVersion = ();
}

impl RegisteredChainExtension<Test> for AssetsExtension<Test> {
    const ID: u16 = 02;
}

parameter_types! {
    pub static ExistentialDeposit: u64 = 1;
}

impl pallet_balances::Config for Test {
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type Balance = Balance;
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type RuntimeHoldReason = RuntimeHoldReason;
    type FreezeIdentifier = ();
    type RuntimeFreezeReason = ();
    type MaxFreezes = ConstU32<0>;
}

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = ConstU64<1>;
    type WeightInfo = ();
}

impl pallet_assets::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Balance = Balance;
    type AssetId = AssetId;
    type AssetIdParameter = u128;
    type Currency = Balances;
    type CreateOrigin = AsEnsureOriginWithArg<frame_system::EnsureSigned<AccountId32>>;
    type ForceOrigin = frame_system::EnsureRoot<AccountId32>;
    type AssetDeposit = ConstU128<1>;
    type AssetAccountDeposit = ConstU128<10>;
    type MetadataDepositBase = ConstU128<1>;
    type MetadataDepositPerByte = ConstU128<1>;
    type ApprovalDeposit = ConstU128<1>;
    type StringLimit = ConstU32<50>;
    type Freezer = ();
    type WeightInfo = ();
    type CallbackHandle = ();
    type Extra = ();
    type RemoveItemsLimit = ConstU32<5>;
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = ();
}

type Block = frame_system::mocking::MockBlockU32<Test>;

frame_support::construct_runtime!(
    pub enum Test
    {
        System: frame_system,
        Balances: pallet_balances,
        Assets: pallet_assets,
        Timestamp: pallet_timestamp,
        Contracts: pallet_contracts,
    }
);

pub const ALICE: AccountId32 = AccountId32::new([1u8; 32]);
pub const BOB: AccountId32 = AccountId32::new([2u8; 32]);
pub const GAS_LIMIT: Weight = Weight::from_parts(100_000_000_000, 700_000);
pub const ONE: u128 = 1_000_000_000_000_000_000;

pub const ASSET_ID: u128 = 1;

impl Convert<Weight, BalanceOf<Self>> for Test {
    fn convert(w: Weight) -> BalanceOf<Self> {
        w.ref_time().into()
    }
}

pub struct ExtBuilder {
    existential_deposit: u64,
}

impl Default for ExtBuilder {
    fn default() -> Self {
        Self {
            existential_deposit: ExistentialDeposit::get(),
        }
    }
}

impl ExtBuilder {
    pub fn existential_deposit(mut self, existential_deposit: u64) -> Self {
        self.existential_deposit = existential_deposit;
        self
    }
    pub fn set_associated_consts(&self) {
        EXISTENTIAL_DEPOSIT.with(|v| *v.borrow_mut() = self.existential_deposit);
    }
    pub fn build(self) -> sp_io::TestExternalities {
        use env_logger::{Builder, Env};
        let env = Env::new().default_filter_or("runtime=debug");
        let _ = Builder::from_env(env).is_test(true).try_init();
        self.set_associated_consts();
        let mut t = frame_system::GenesisConfig::<Test>::default()
            .build_storage()
            .unwrap();
        pallet_balances::GenesisConfig::<Test> { balances: vec![] }
            .assimilate_storage(&mut t)
            .unwrap();
        let mut ext = sp_io::TestExternalities::new(t);
        ext.execute_with(|| System::set_block_number(1));
        ext
    }
}
