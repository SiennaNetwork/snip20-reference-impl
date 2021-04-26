#![cfg(test)]
mod test_helpers; use test_helpers::*;

#[test]
fn test_query_token_info() {
    let init_name = "sec-sec".to_string();
    let init_admin = HumanAddr("admin".to_string());
    let init_symbol = "SECSEC".to_string();
    let init_decimals = 8;
    let init_config: InitConfig = from_binary(&Binary::from(
        r#"{ "public_total_supply": true }"#.as_bytes(),
    ))
    .unwrap();
    let init_supply = Uint128(5000);

    let mut deps = mock_dependencies(20, &[]);
    let env = mock_env("instantiator", &[]);
    let init_msg = InitMsg {
        name: init_name.clone(),
        admin: Some(init_admin.clone()),
        symbol: init_symbol.clone(),
        decimals: init_decimals.clone(),
        initial_balances: Some(vec![InitialBalance {
            address: HumanAddr("giannis".to_string()),
            amount: init_supply,
        }]),
        prng_seed: Binary::from("lolz fun yay".as_bytes()),
        config: Some(init_config),
    };
    let init_result = init(&mut deps, env, init_msg);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let query_msg = QueryMsg::TokenInfo {};
    let query_result = query(&deps, query_msg);
    assert!(
        query_result.is_ok(),
        "Init failed: {}",
        query_result.err().unwrap()
    );
    let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
    match query_answer {
        QueryAnswer::TokenInfo {
            name,
            symbol,
            decimals,
            total_supply,
        } => {
            assert_eq!(name, init_name);
            assert_eq!(symbol, init_symbol);
            assert_eq!(decimals, init_decimals);
            assert_eq!(total_supply, Some(Uint128(5000)));
        }
        _ => panic!("unexpected"),
    }
}

#[test]
fn test_query_allowance() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("giannis".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::IncreaseAllowance {
        spender: HumanAddr("lebron".to_string()),
        amount: Uint128(2000),
        padding: None,
        expiration: None,
    };
    let handle_result = handle(&mut deps, mock_env("giannis", &[]), handle_msg);
    assert!(
        handle_result.is_ok(),
        "handle() failed: {}",
        handle_result.err().unwrap()
    );

    let vk1 = ViewingKey("key1".to_string());
    let vk2 = ViewingKey("key2".to_string());

    let query_msg = QueryMsg::Allowance {
        owner: HumanAddr("giannis".to_string()),
        spender: HumanAddr("lebron".to_string()),
        key: vk1.0.clone(),
    };
    let query_result = query(&deps, query_msg);
    assert!(
        query_result.is_ok(),
        "Query failed: {}",
        query_result.err().unwrap()
    );
    let error = extract_error_msg(query_result);
    assert!(error.contains("Wrong viewing key"));

    let handle_msg = HandleMsg::SetViewingKey {
        key: vk1.0.clone(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("lebron", &[]), handle_msg);
    let unwrapped_result: HandleAnswer =
        from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
    assert_eq!(
        to_binary(&unwrapped_result).unwrap(),
        to_binary(&HandleAnswer::SetViewingKey {
            status: ResponseStatus::Success
        })
        .unwrap(),
    );

    let handle_msg = HandleMsg::SetViewingKey {
        key: vk2.0.clone(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("giannis", &[]), handle_msg);
    let unwrapped_result: HandleAnswer =
        from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
    assert_eq!(
        to_binary(&unwrapped_result).unwrap(),
        to_binary(&HandleAnswer::SetViewingKey {
            status: ResponseStatus::Success
        })
        .unwrap(),
    );

    let query_msg = QueryMsg::Allowance {
        owner: HumanAddr("giannis".to_string()),
        spender: HumanAddr("lebron".to_string()),
        key: vk1.0.clone(),
    };
    let query_result = query(&deps, query_msg);
    let allowance = match from_binary(&query_result.unwrap()).unwrap() {
        QueryAnswer::Allowance { allowance, .. } => allowance,
        _ => panic!("Unexpected"),
    };
    assert_eq!(allowance, Uint128(2000));

    let query_msg = QueryMsg::Allowance {
        owner: HumanAddr("giannis".to_string()),
        spender: HumanAddr("lebron".to_string()),
        key: vk2.0.clone(),
    };
    let query_result = query(&deps, query_msg);
    let allowance = match from_binary(&query_result.unwrap()).unwrap() {
        QueryAnswer::Allowance { allowance, .. } => allowance,
        _ => panic!("Unexpected"),
    };
    assert_eq!(allowance, Uint128(2000));

    let query_msg = QueryMsg::Allowance {
        owner: HumanAddr("lebron".to_string()),
        spender: HumanAddr("giannis".to_string()),
        key: vk2.0.clone(),
    };
    let query_result = query(&deps, query_msg);
    let allowance = match from_binary(&query_result.unwrap()).unwrap() {
        QueryAnswer::Allowance { allowance, .. } => allowance,
        _ => panic!("Unexpected"),
    };
    assert_eq!(allowance, Uint128(0));
}

#[test]
fn test_query_balance() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::SetViewingKey {
        key: "key".to_string(),
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

    let query_msg = QueryMsg::Balance {
        address: HumanAddr("bob".to_string()),
        key: "wrong_key".to_string(),
    };
    let query_result = query(&deps, query_msg);
    let error = extract_error_msg(query_result);
    assert!(error.contains("Wrong viewing key"));

    let query_msg = QueryMsg::Balance {
        address: HumanAddr("bob".to_string()),
        key: "key".to_string(),
    };
    let query_result = query(&deps, query_msg);
    let balance = match from_binary(&query_result.unwrap()).unwrap() {
        QueryAnswer::Balance { amount } => amount,
        _ => panic!("Unexpected"),
    };
    assert_eq!(balance, Uint128(5000));
}

#[test]
fn test_query_transfer_history() {
    let (init_result, mut deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("bob".to_string()),
        amount: Uint128(5000),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::SetViewingKey {
        key: "key".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(ensure_success(handle_result.unwrap()));

    let handle_msg = HandleMsg::Transfer {
        recipient: HumanAddr("alice".to_string()),
        amount: Uint128(1000),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let result = handle_result.unwrap();
    assert!(ensure_success(result));
    let handle_msg = HandleMsg::Transfer {
        recipient: HumanAddr("banana".to_string()),
        amount: Uint128(500),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let result = handle_result.unwrap();
    assert!(ensure_success(result));
    let handle_msg = HandleMsg::Transfer {
        recipient: HumanAddr("mango".to_string()),
        amount: Uint128(2500),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let result = handle_result.unwrap();
    assert!(ensure_success(result));

    let query_msg = QueryMsg::TransferHistory {
        address: HumanAddr("bob".to_string()),
        key: "key".to_string(),
        page: None,
        page_size: 0,
    };
    let query_result = query(&deps, query_msg);
    // let a: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
    // println!("{:?}", a);
    let transfers = match from_binary(&query_result.unwrap()).unwrap() {
        QueryAnswer::TransferHistory { txs } => txs,
        _ => panic!("Unexpected"),
    };
    assert!(transfers.is_empty());

    let query_msg = QueryMsg::TransferHistory {
        address: HumanAddr("bob".to_string()),
        key: "key".to_string(),
        page: None,
        page_size: 10,
    };
    let query_result = query(&deps, query_msg);
    let transfers = match from_binary(&query_result.unwrap()).unwrap() {
        QueryAnswer::TransferHistory { txs } => txs,
        _ => panic!("Unexpected"),
    };
    assert_eq!(transfers.len(), 3);

    let query_msg = QueryMsg::TransferHistory {
        address: HumanAddr("bob".to_string()),
        key: "key".to_string(),
        page: None,
        page_size: 2,
    };
    let query_result = query(&deps, query_msg);
    let transfers = match from_binary(&query_result.unwrap()).unwrap() {
        QueryAnswer::TransferHistory { txs } => txs,
        _ => panic!("Unexpected"),
    };
    assert_eq!(transfers.len(), 2);
}
