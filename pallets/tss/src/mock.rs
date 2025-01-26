use crate as pallet_tss;
use frame_support::{derive_impl, parameter_types};
use frame_system::{self as system, Origin};
use sp_core::{sr25519::Public, ConstU16, ConstU32, H256};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
    BuildStorage,
};


// The AccountId alias in this test module.
pub type AccountId = Public;


// Configure a mock runtime to test the pallet.
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
//    type AccountData = pallet_balances::AccountData<Balance>;
   type OnNewAccount = ();
   type OnKilledAccount = ();
   type SystemWeightInfo = ();
   type SS58Prefix = ConstU16<42>;
   type OnSetCode = ();
   type MaxConsumers = ConstU32<16>;
}

impl crate::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    
    type MaxNumberOfShares = ConstU32<16>;
}

frame_support::construct_runtime!(
    pub enum Test
    {
        System: frame_system,
        TestingPallet: crate::pallet,
    }
);

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();

    t.into()
}