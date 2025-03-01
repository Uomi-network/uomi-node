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

use crate::mock::*;
use crate::*;

use frame_support::assert_ok;
use precompile_utils::testing::*;

fn precompiles() -> TestPrecompileSet<TestRuntime> {
    PrecompilesValue::get()
}

#[test]
fn test_get_evm_address() {
    // Case 1 : Address Not Mapped
    ExtBuilder::default().build().execute_with(|| {
        let alice_default_evm =
            <TestRuntime as pallet_unified_accounts::Config>::DefaultMappings::to_default_h160(
                &ALICE,
            );

        let res: (Address, bool) = (alice_default_evm.into(), false);
        precompiles()
            .prepare_test(
                TestAccount::Viktor,
                PRECOMPILE_ADDRESS,
                PrecompileCall::get_evm_address_or_default {
                    account_id: H256::zero(), // Alice's Address
                },
            )
            .expect_no_logs()
            .execute_returns(res);
    });

    // Case 2 : Address Mapped
    ExtBuilder::default().build().execute_with(|| {
        let alice_eth = UnifiedAccounts::eth_address(&alice_secret());
        let signature = get_evm_signature(&ALICE, &alice_secret());

        // claim the account
        assert_ok!(UnifiedAccounts::claim_evm_address(
            RuntimeOrigin::signed(ALICE),
            alice_eth,
            signature
        ));

        let res: (Address, bool) = (alice_eth.into(), true);
        precompiles()
            .prepare_test(
                TestAccount::Viktor,
                PRECOMPILE_ADDRESS,
                PrecompileCall::get_evm_address_or_default {
                    account_id: H256::zero(), // Alice's Address
                },
            )
            .expect_no_logs()
            .execute_returns(res);
    });
}

#[test]
fn test_get_native_address() {
    // Case 1: not mapped native address (default address)
    ExtBuilder::default().build().execute_with(|| {
        let alice_eth = UnifiedAccounts::eth_address(&alice_secret());
        let alice_eth_address: Address = alice_eth.into();

        // default ss58 account associated with eth address
        let alice_eth_old_account =
            <TestRuntime as pallet_unified_accounts::Config>::DefaultMappings::to_default_account_id(
                &alice_eth,
            );

        // for let binding
        let alice_eth_old_account_converted: &[u8; 32] = alice_eth_old_account.as_ref();
        let res: (H256, bool) = (alice_eth_old_account_converted.into(), false);
        precompiles()
            .prepare_test(
                TestAccount::Viktor,
                PRECOMPILE_ADDRESS,
                PrecompileCall::get_native_address_or_default { evm_address: alice_eth_address }
            )
            .expect_no_logs()
            .execute_returns(res);
    });

    // Case 2 : mapped address
    ExtBuilder::default().build().execute_with(|| {
        // claiming address
        let alice_eth: Address = UnifiedAccounts::eth_address(&alice_secret()).into();
        let signature = get_evm_signature(&ALICE, &alice_secret());

        // claim the account
        assert_ok!(UnifiedAccounts::claim_evm_address(
            RuntimeOrigin::signed(ALICE),
            alice_eth.into(),
            signature
        ));

        let alice_converted: &[u8; 32] = ALICE.as_ref();

        let res: (H256, bool) = (alice_converted.into(), true);
        precompiles()
            .prepare_test(
                TestAccount::Viktor,
                PRECOMPILE_ADDRESS,
                PrecompileCall::get_native_address_or_default {
                    evm_address: alice_eth,
                },
            )
            .expect_no_logs()
            .execute_returns(res);
    });
}
