use crate::mock::*;
use frame_support::{assert_ok, traits::Currency, BoundedVec};
use pallet_evm::AddressMapping;
use pallet_ipfs::{AgentsPins, CidsStatus};
use pallet_uomi_engine::{
    types::{InferenceMetrics, ModelPrice},
    ModelPricing, NodesOutputs, OpocAssignment, OpocLevel, PendingInferencePayments,
};
use precompile_utils::testing::*;
use sp_core::{H160, U256};

fn precompiles() -> TestPrecompileSet<TestRuntime> {
    PrecompilesValue::get()
}

fn account(address: H160) -> AccountId {
    AddressMapper::into_account_id(address)
}

fn validator(byte: u8) -> AccountId {
    AccountId::from_raw([byte; 32])
}

fn set_price(nft_id: U256) {
    ModelPricing::<TestRuntime>::insert(
        nft_id,
        ModelPrice {
            price_per_input_token: 10,
            price_per_output_token: 30,
            base_fee: 1_000,
        },
    );
}

fn set_agent_cid(nft_id: U256) {
    let cid = BoundedVec::try_from(b"agent-cid".to_vec()).expect("cid fits bound");
    AgentsPins::<TestRuntime>::insert(nft_id, cid.clone());
    CidsStatus::<TestRuntime>::insert(cid, (U256::zero(), U256::from(1)));
}

#[test]
fn quote_inference_returns_expected_cost() {
    ExtBuilder::default().build().execute_with(|| {
        let nft_id = U256::from(1);
        set_price(nft_id);

        precompiles()
            .prepare_test(
                USER,
                PRECOMPILE_ADDRESS,
                PrecompileCall::quote_inference {
                    nft_id,
                    input_size: U256::from(12),
                    min_validators: U256::from(3),
                    max_output_tokens: U256::from(20),
                },
            )
            .expect_no_logs()
            .execute_returns(U256::from(2_890u128));
    });
}

#[test]
fn call_agent_reverts_when_underpaid() {
    ExtBuilder::default().build().execute_with(|| {
        let nft_id = U256::from(1);
        set_price(nft_id);

        precompiles()
            .prepare_test(
                AGENT_CONTRACT,
                PRECOMPILE_ADDRESS,
                PrecompileCall::call_agent_payable {
                    request_id: U256::from(42),
                    nft_id,
                    sender: USER.into(),
                    data: vec![1, 2, 3].into(),
                    data_cid: Vec::<u8>::new().into(),
                    min_validators: U256::from(3),
                    min_blocks: U256::from(10),
                    max_output_tokens: U256::from(20),
                },
            )
            .with_value(U256::from(1_000u128))
            .expect_no_logs()
            .execute_reverts(|output| output == b"Insufficient inference payment");
    });
}

#[test]
fn call_agent_reverts_for_non_agent_contract() {
    ExtBuilder::default().build().execute_with(|| {
        let nft_id = U256::from(1);
        set_price(nft_id);
        set_agent_cid(nft_id);

        precompiles()
            .prepare_test(
                H160::repeat_byte(0xAB),
                PRECOMPILE_ADDRESS,
                PrecompileCall::call_agent_payable {
                    request_id: U256::from(42),
                    nft_id,
                    sender: USER.into(),
                    data: vec![1, 2, 3].into(),
                    data_cid: Vec::<u8>::new().into(),
                    min_validators: U256::from(3),
                    min_blocks: U256::from(10),
                    max_output_tokens: U256::from(20),
                },
            )
            .with_value(U256::from(10_000u128))
            .expect_no_logs()
            .execute_reverts(|output| output == b"Only the agent contract can call this function");
    });
}

#[test]
fn payable_call_agent_starts_payment_and_settlement_rewards_validators() {
    ExtBuilder::default().build().execute_with(|| {
        let request_id = U256::from(42);
        let nft_id = U256::from(1);
        let min_validators = U256::from(3);
        let max_output_tokens = 20u32;
        let input = vec![1, 2, 3];
        let payer = account(USER);
        let escrow = account(PRECOMPILE_ADDRESS);
        let validator_0 = validator(1);
        let validator_1 = validator(2);
        let validator_2 = validator(3);
        let output = BoundedVec::try_from(vec![9, 9, 9]).expect("output fits bound");
        let metrics = InferenceMetrics {
            tokens_in: 2,
            tokens_out: 3,
        };

        set_price(nft_id);
        set_agent_cid(nft_id);
        let paid = pallet_uomi_engine::Pallet::<TestRuntime>::quote_inference_for_request_v1(
            nft_id,
            input.len() as u32,
            min_validators,
            max_output_tokens,
        )
        .expect("quote should be calculated");

        let _ = <Balances as Currency<AccountId>>::make_free_balance_be(&escrow, paid);

        precompiles()
            .prepare_test(
                AGENT_CONTRACT,
                PRECOMPILE_ADDRESS,
                PrecompileCall::call_agent_payable {
                    request_id,
                    nft_id,
                    sender: USER.into(),
                    data: input.into(),
                    data_cid: Vec::<u8>::new().into(),
                    min_validators,
                    min_blocks: U256::from(10),
                    max_output_tokens: U256::from(max_output_tokens),
                },
            )
            .with_value(U256::from(paid))
            .expect_no_logs()
            .execute_returns(true);

        assert_eq!(
            PendingInferencePayments::<TestRuntime>::get(request_id),
            Some((payer.clone(), escrow.clone(), paid))
        );

        OpocAssignment::<TestRuntime>::insert(
            request_id,
            validator_0.clone(),
            (U256::from(10), OpocLevel::Level0),
        );
        OpocAssignment::<TestRuntime>::insert(
            request_id,
            validator_1.clone(),
            (U256::from(10), OpocLevel::Level1),
        );
        OpocAssignment::<TestRuntime>::insert(
            request_id,
            validator_2.clone(),
            (U256::from(10), OpocLevel::Level1),
        );
        NodesOutputs::<TestRuntime>::insert(request_id, validator_0.clone(), output.clone());
        NodesOutputs::<TestRuntime>::insert(request_id, validator_1.clone(), output.clone());
        NodesOutputs::<TestRuntime>::insert(request_id, validator_2.clone(), output.clone());

        assert_ok!(pallet_uomi_engine::Pallet::<TestRuntime>::settle_inference_payment(
            &request_id,
            &output,
            metrics,
            min_validators,
            nft_id,
        ));

        let actual_cost = 1_000 + ((2 * 10) + (3 * 30)) * 3;
        let reward = actual_cost / 3;
        let distributed = reward * 3;

        assert_eq!(Balances::free_balance(&validator_0), reward);
        assert_eq!(Balances::free_balance(&validator_1), reward);
        assert_eq!(Balances::free_balance(&validator_2), reward);
        assert_eq!(Balances::free_balance(&payer), paid - distributed);
        assert_eq!(Balances::free_balance(&escrow), 0);
        assert!(!PendingInferencePayments::<TestRuntime>::contains_key(request_id));
    });
}
