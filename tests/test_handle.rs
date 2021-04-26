#![cfg(test)]
mod test_helpers; use test_helpers::*;

// Handle tests

#[test]
fn test_handle_transfer() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::Transfer {
        recipient: HumanAddr("alice".to_string()),
        amount: Uint128(1000),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let result = handle_result.unwrap();
    assert!(ensure_success(result));
    let bob_canonical = deps
        .api
        .canonical_address(&HumanAddr("bob".to_string()))
        .unwrap();
    let alice_canonical = deps
        .api
        .canonical_address(&HumanAddr("alice".to_string()))
        .unwrap();
    let balances = ReadonlyBalances::from_storage(&deps.storage);
    assert_eq!(5000 - 1000, balances.account_amount(&bob_canonical));
    assert_eq!(1000, balances.account_amount(&alice_canonical));

    let handle_msg = HandleMsg::Transfer {
        recipient: HumanAddr("alice".to_string()),
        amount: Uint128(10000),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("insufficient funds"));
}

#[test]
fn test_handle_send() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::RegisterReceive {
        code_hash: "this_is_a_hash_of_a_code".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("contract", &[]), handle_msg);
    let result = handle_result.unwrap();
    assert!(ensure_success(result));

    let handle_msg = HandleMsg::Send {
        recipient: HumanAddr("contract".to_string()),
        amount: Uint128(100),
        padding: None,
        msg: Some(to_binary("hey hey you you").unwrap()),
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let result = handle_result.unwrap();
    assert!(ensure_success(result.clone()));
    assert!(result.messages.contains(&CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: HumanAddr("contract".to_string()),
        callback_code_hash: "this_is_a_hash_of_a_code".to_string(),
        msg: Snip20ReceiveMsg::new(
            HumanAddr("bob".to_string()),
            HumanAddr("bob".to_string()),
            Uint128(100),
            Some(to_binary("hey hey you you").unwrap())
        )
        .into_binary()
        .unwrap(),
        send: vec![]
    })));
}

#[test]
fn test_handle_register_receive() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::RegisterReceive {
        code_hash: "this_is_a_hash_of_a_code".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("contract", &[]), handle_msg);
    let result = handle_result.unwrap();
    assert!(ensure_success(result));

    let hash = get_receiver_hash(&deps.storage, &HumanAddr("contract".to_string()))
        .unwrap()
        .unwrap();
    assert_eq!(hash, "this_is_a_hash_of_a_code".to_string());
}

#[test]
fn test_handle_create_viewing_key() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::CreateViewingKey {
        entropy: "".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "handle() failed: {}",
        handle_result.err().unwrap()
    );
    let answer: HandleAnswer = from_binary(&handle_result.unwrap().data.unwrap()).unwrap();

    let key = match answer {
        HandleAnswer::CreateViewingKey { key } => key,
        _ => panic!("NOPE"),
    };
    let bob_canonical = deps
        .api
        .canonical_address(&HumanAddr("bob".to_string()))
        .unwrap();
    let saved_vk = read_viewing_key(&deps.storage, &bob_canonical).unwrap();
    assert!(key.check_viewing_key(saved_vk.as_slice()));
}

#[test]
fn test_handle_set_viewing_key() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // Set VK
    let handle_msg = HandleMsg::SetViewingKey {
        key: "hi lol".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let unwrapped_result: HandleAnswer =
        from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
    assert_eq!(
        to_binary(&unwrapped_result).unwrap(),
        to_binary(&HandleAnswer::SetViewingKey {
            status: ResponseStatus::Success
        })
        .unwrap(),
    );

    // Set valid VK
    let actual_vk = ViewingKey("x".to_string().repeat(VIEWING_KEY_SIZE));
    let handle_msg = HandleMsg::SetViewingKey {
        key: actual_vk.0.clone(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let unwrapped_result: HandleAnswer =
        from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
    assert_eq!(
        to_binary(&unwrapped_result).unwrap(),
        to_binary(&HandleAnswer::SetViewingKey { status: ResponseStatus::Success }).unwrap(),
    );
    let bob_canonical = deps
        .api
        .canonical_address(&HumanAddr("bob".to_string()))
        .unwrap();
    let saved_vk = read_viewing_key(&deps.storage, &bob_canonical).unwrap();
    assert!(actual_vk.check_viewing_key(&saved_vk));
}

#[test]
fn test_handle_transfer_from() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // Transfer before allowance
    let handle_msg = HandleMsg::TransferFrom {
        owner: HumanAddr("bob".to_string()),
        recipient: HumanAddr("alice".to_string()),
        amount: Uint128(2500),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("insufficient allowance"));

    // Transfer more than allowance
    let handle_msg = HandleMsg::IncreaseAllowance {
        spender: HumanAddr("alice".to_string()),
        amount: Uint128(2000),
        padding: None,
        expiration: Some(1_571_797_420),
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "handle() failed: {}",
        handle_result.err().unwrap()
    );
    let handle_msg = HandleMsg::TransferFrom {
        owner: HumanAddr("bob".to_string()),
        recipient: HumanAddr("alice".to_string()),
        amount: Uint128(2500),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("insufficient allowance"));

    // Transfer after allowance expired
    let handle_msg = HandleMsg::TransferFrom {
        owner: HumanAddr("bob".to_string()),
        recipient: HumanAddr("alice".to_string()),
        amount: Uint128(2000),
        padding: None,
    };
    let handle_result = handle(
        &mut deps,
        Env {
            block: BlockInfo {
                height: 12_345,
                time: 1_571_797_420,
                chain_id: "cosmos-testnet-14002".to_string(),
            },
            message: MessageInfo {
                sender: HumanAddr("bob".to_string()),
                sent_funds: vec![],
            },
            contract: ContractInfo {
                address: HumanAddr::from(MOCK_CONTRACT_ADDR),
            },
            contract_key: Some("".to_string()),
            contract_code_hash: "".to_string(),
        },
        handle_msg,
    );
    let error = extract_error_msg(handle_result);
    assert!(error.contains("insufficient allowance"));

    // Sanity check
    let handle_msg = HandleMsg::TransferFrom {
        owner: HumanAddr("bob".to_string()),
        recipient: HumanAddr("alice".to_string()),
        amount: Uint128(2000),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "handle() failed: {}",
        handle_result.err().unwrap()
    );
    let bob_canonical = deps
        .api
        .canonical_address(&HumanAddr("bob".to_string()))
        .unwrap();
    let alice_canonical = deps
        .api
        .canonical_address(&HumanAddr("alice".to_string()))
        .unwrap();
    let bob_balance = ReadonlyBalances::from_storage(&deps.storage)
        .account_amount(&bob_canonical);
    let alice_balance = ReadonlyBalances::from_storage(&deps.storage)
        .account_amount(&alice_canonical);
    assert_eq!(bob_balance, 5000 - 2000);
    assert_eq!(alice_balance, 2000);
    let total_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
    assert_eq!(total_supply, 5000);

    // Second send more than allowance
    let handle_msg = HandleMsg::TransferFrom {
        owner: HumanAddr("bob".to_string()),
        recipient: HumanAddr("alice".to_string()),
        amount: Uint128(1),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("insufficient allowance"));
}

#[test]
fn test_handle_send_from() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // Send before allowance
    let handle_msg = HandleMsg::SendFrom {
        owner: HumanAddr("bob".to_string()),
        recipient: HumanAddr("alice".to_string()),
        amount: Uint128(2500),
        msg: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("insufficient allowance"));

    // Send more than allowance
    let handle_msg = HandleMsg::IncreaseAllowance {
        spender: HumanAddr("alice".to_string()),
        amount: Uint128(2000),
        padding: None,
        expiration: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "handle() failed: {}",
        handle_result.err().unwrap()
    );
    let handle_msg = HandleMsg::SendFrom {
        owner: HumanAddr("bob".to_string()),
        recipient: HumanAddr("alice".to_string()),
        amount: Uint128(2500),
        msg: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("insufficient allowance"));

    // Sanity check
    let handle_msg = HandleMsg::RegisterReceive {
        code_hash: "lolz".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("contract", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "handle() failed: {}",
        handle_result.err().unwrap()
    );
    let send_msg = Binary::from(r#"{ "some_msg": { "some_key": "some_val" } }"#.as_bytes());
    let snip20_msg = Snip20ReceiveMsg::new(
        HumanAddr("alice".to_string()),
        HumanAddr("bob".to_string()),
        Uint128(2000),
        Some(send_msg.clone()),
    );
    let handle_msg = HandleMsg::SendFrom {
        owner: HumanAddr("bob".to_string()),
        recipient: HumanAddr("contract".to_string()),
        amount: Uint128(2000),
        msg: Some(send_msg),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "handle() failed: {}",
        handle_result.err().unwrap()
    );
    assert!(handle_result.unwrap().messages.contains(
        &snip20_msg
            .into_cosmos_msg("lolz".to_string(), HumanAddr("contract".to_string()))
            .unwrap()
    ));
    let bob_canonical = deps
        .api
        .canonical_address(&HumanAddr("bob".to_string()))
        .unwrap();
    let contract_canonical = deps
        .api
        .canonical_address(&HumanAddr("contract".to_string()))
        .unwrap();
    let bob_balance = ReadonlyBalances::from_storage(&deps.storage)
        .account_amount(&bob_canonical);
    let contract_balance = ReadonlyBalances::from_storage(&deps.storage)
        .account_amount(&contract_canonical);
    assert_eq!(bob_balance, 5000 - 2000);
    assert_eq!(contract_balance, 2000);
    let total_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
    assert_eq!(total_supply, 5000);

    // Second send more than allowance
    let handle_msg = HandleMsg::SendFrom {
        owner: HumanAddr("bob".to_string()),
        recipient: HumanAddr("alice".to_string()),
        amount: Uint128(1),
        msg: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("insufficient allowance"));
}

#[test]
fn test_handle_decrease_allowance() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::DecreaseAllowance {
        spender: HumanAddr("alice".to_string()),
        amount: Uint128(2000),
        padding: None,
        expiration: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "handle() failed: {}",
        handle_result.err().unwrap()
    );

    let bob_canonical = deps
        .api
        .canonical_address(&HumanAddr("bob".to_string()))
        .unwrap();
    let alice_canonical = deps
        .api
        .canonical_address(&HumanAddr("alice".to_string()))
        .unwrap();

    let allowance = read_allowance(&deps.storage, &bob_canonical, &alice_canonical).unwrap();
    assert_eq!(
        allowance,
        Allowance {
            amount: 0,
            expiration: None
        }
    );

    let handle_msg = HandleMsg::IncreaseAllowance {
        spender: HumanAddr("alice".to_string()),
        amount: Uint128(2000),
        padding: None,
        expiration: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "handle() failed: {}",
        handle_result.err().unwrap()
    );

    let handle_msg = HandleMsg::DecreaseAllowance {
        spender: HumanAddr("alice".to_string()),
        amount: Uint128(50),
        padding: None,
        expiration: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "handle() failed: {}",
        handle_result.err().unwrap()
    );

    let allowance = read_allowance(&deps.storage, &bob_canonical, &alice_canonical).unwrap();
    assert_eq!(
        allowance,
        Allowance {
            amount: 1950,
            expiration: None
        }
    );
}

#[test]
fn test_handle_increase_allowance() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::IncreaseAllowance {
        spender: HumanAddr("alice".to_string()),
        amount: Uint128(2000),
        padding: None,
        expiration: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "handle() failed: {}",
        handle_result.err().unwrap()
    );

    let bob_canonical = deps
        .api
        .canonical_address(&HumanAddr("bob".to_string()))
        .unwrap();
    let alice_canonical = deps
        .api
        .canonical_address(&HumanAddr("alice".to_string()))
        .unwrap();

    let allowance = read_allowance(&deps.storage, &bob_canonical, &alice_canonical).unwrap();
    assert_eq!(
        allowance,
        Allowance {
            amount: 2000,
            expiration: None
        }
    );

    let handle_msg = HandleMsg::IncreaseAllowance {
        spender: HumanAddr("alice".to_string()),
        amount: Uint128(2000),
        padding: None,
        expiration: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "handle() failed: {}",
        handle_result.err().unwrap()
    );

    let allowance = read_allowance(&deps.storage, &bob_canonical, &alice_canonical).unwrap();
    assert_eq!(
        allowance,
        Allowance {
            amount: 4000,
            expiration: None
        }
    );
}

#[test]
fn test_handle_change_admin() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::ChangeAdmin {
        address: HumanAddr("bob".to_string()),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "handle() failed: {}",
        handle_result.err().unwrap()
    );

    let admin = ReadonlyConfig::from_storage(&deps.storage)
        .constants()
        .unwrap()
        .admin;
    assert_eq!(admin, HumanAddr("bob".to_string()));
}

#[test]
fn test_handle_set_contract_status() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("admin".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::SetContractStatus {
        level: ContractStatusLevel::StopAll,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "handle() failed: {}",
        handle_result.err().unwrap()
    );

    let contract_status = ReadonlyConfig::from_storage(&deps.storage).contract_status();
    assert!(matches!(contract_status, ContractStatusLevel::StopAll{..}));
}

#[test]
fn test_handle_mint() {
    let initial_amount: u128 = 5000;
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("lebron".to_string()),
        amount: Uint128(initial_amount),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
    let mint_amount: u128 = 100;
    let handle_msg = HandleMsg::Mint {
        recipient: HumanAddr("lebron".to_string()),
        amount: Uint128(mint_amount),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "Pause handle failed: {}",
        handle_result.err().unwrap()
    );

    let new_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
    assert_eq!(new_supply, supply + mint_amount);
}

#[test]
fn test_handle_admin_commands() {
    let admin_err = "Admin commands can only be run from admin address".to_string();

    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("lebron".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let pause_msg = HandleMsg::SetContractStatus {
        level: ContractStatusLevel::StopAll,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("not_admin", &[]), pause_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains(&admin_err.clone()));

    let mint_msg = HandleMsg::AddMinters {
        minters: vec![HumanAddr("not_admin".to_string())],
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("not_admin", &[]), mint_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains(&admin_err.clone()));

    let mint_msg = HandleMsg::RemoveMinters {
        minters: vec![HumanAddr("admin".to_string())],
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("not_admin", &[]), mint_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains(&admin_err.clone()));

    let mint_msg = HandleMsg::SetMinters {
        minters: vec![HumanAddr("not_admin".to_string())],
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("not_admin", &[]), mint_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains(&admin_err.clone()));

    let change_admin_msg = HandleMsg::ChangeAdmin {
        address: HumanAddr("not_admin".to_string()),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("not_admin", &[]), change_admin_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains(&admin_err.clone()));
}

#[test]
fn test_handle_pause_all() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("lebron".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let pause_msg = HandleMsg::SetContractStatus {
        level: ContractStatusLevel::StopAll,
        padding: None,
    };

    let handle_result = handle(&mut deps, mock_env("admin", &[]), pause_msg);
    assert!(
        handle_result.is_ok(),
        "Pause handle failed: {}",
        handle_result.err().unwrap()
    );

    let send_msg = HandleMsg::Transfer {
        recipient: HumanAddr("account".to_string()),
        amount: Uint128(123),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), send_msg);
    let error = extract_error_msg(handle_result);
    assert_eq!(
        error,
        "This contract is stopped and this action is not allowed".to_string()
    );

    let withdraw_msg = HandleMsg::Redeem {
        amount: Uint128(5000),
        denom: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("lebron", &[]), withdraw_msg);
    let error = extract_error_msg(handle_result);
    assert_eq!(
        error,
        "This contract is stopped and this action is not allowed".to_string()
    );
}

#[test]
fn test_handle_set_minters() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::SetMinters {
        minters: vec![HumanAddr("bob".to_string())],
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("Admin commands can only be run from admin address"));

    let handle_msg = HandleMsg::SetMinters {
        minters: vec![HumanAddr("bob".to_string())],
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(ensure_success(handle_result.unwrap()));

    let handle_msg = HandleMsg::Mint {
        recipient: HumanAddr("bob".to_string()),
        amount: Uint128(100),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(ensure_success(handle_result.unwrap()));

    let handle_msg = HandleMsg::Mint {
        recipient: HumanAddr("bob".to_string()),
        amount: Uint128(100),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("allowed to minter accounts only"));
}

#[test]
fn test_handle_add_minters() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::AddMinters {
        minters: vec![HumanAddr("bob".to_string())],
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("Admin commands can only be run from admin address"));

    let handle_msg = HandleMsg::AddMinters {
        minters: vec![HumanAddr("bob".to_string())],
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(ensure_success(handle_result.unwrap()));

    let handle_msg = HandleMsg::Mint {
        recipient: HumanAddr("bob".to_string()),
        amount: Uint128(100),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(ensure_success(handle_result.unwrap()));

    let handle_msg = HandleMsg::Mint {
        recipient: HumanAddr("bob".to_string()),
        amount: Uint128(100),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(ensure_success(handle_result.unwrap()));
}

#[test]
fn test_handle_remove_minters() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::RemoveMinters {
        minters: vec![HumanAddr("admin".to_string())],
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("Admin commands can only be run from admin address"));

    let handle_msg = HandleMsg::RemoveMinters {
        minters: vec![HumanAddr("admin".to_string())],
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(ensure_success(handle_result.unwrap()));

    let handle_msg = HandleMsg::Mint {
        recipient: HumanAddr("bob".to_string()),
        amount: Uint128(100),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("allowed to minter accounts only"));

    let handle_msg = HandleMsg::Mint {
        recipient: HumanAddr("bob".to_string()),
        amount: Uint128(100),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("allowed to minter accounts only"));

    // Removing another extra time to ensure nothing funky happens
    let handle_msg = HandleMsg::RemoveMinters {
        minters: vec![HumanAddr("admin".to_string())],
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(ensure_success(handle_result.unwrap()));

    let handle_msg = HandleMsg::Mint {
        recipient: HumanAddr("bob".to_string()),
        amount: Uint128(100),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("allowed to minter accounts only"));

    let handle_msg = HandleMsg::Mint {
        recipient: HumanAddr("bob".to_string()),
        amount: Uint128(100),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("allowed to minter accounts only"));
}

// Query tests

#[test]
fn test_authenticated_queries() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("giannis".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let no_vk_yet_query_msg = QueryMsg::Balance {
        address: HumanAddr("giannis".to_string()),
        key: "no_vk_yet".to_string(),
    };
    let query_result = query(&deps, no_vk_yet_query_msg);
    let error = extract_error_msg(query_result);
    assert_eq!(
        error,
        "Wrong viewing key for this address or viewing key not set".to_string()
    );

    let create_vk_msg = HandleMsg::CreateViewingKey {
        entropy: "34".to_string(),
        padding: None,
    };
    let handle_response = handle(&mut deps, mock_env("giannis", &[]), create_vk_msg).unwrap();
    let vk = match from_binary(&handle_response.data.unwrap()).unwrap() {
        HandleAnswer::CreateViewingKey { key } => key,
        _ => panic!("Unexpected result from handle"),
    };

    let query_balance_msg = QueryMsg::Balance {
        address: HumanAddr("giannis".to_string()),
        key: vk.0,
    };

    let query_response = query(&deps, query_balance_msg).unwrap();
    let balance = match from_binary(&query_response).unwrap() {
        QueryAnswer::Balance { amount } => amount,
        _ => panic!("Unexpected result from query"),
    };
    assert_eq!(balance, Uint128(5000));

    let wrong_vk_query_msg = QueryMsg::Balance {
        address: HumanAddr("giannis".to_string()),
        key: "wrong_vk".to_string(),
    };
    let query_result = query(&deps, wrong_vk_query_msg);
    let error = extract_error_msg(query_result);
    assert_eq!(
        error,
        "Wrong viewing key for this address or viewing key not set".to_string()
    );
}
