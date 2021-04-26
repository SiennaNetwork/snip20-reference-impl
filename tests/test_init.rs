#![cfg(test)]
mod test_helpers; use test_helpers::*;

// Init tests

#[test]
fn test_init_sanity() {
    let (init_result, deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("lebron".to_string()),
        amount: Uint128(5000),
    }]);
    assert_eq!(init_result.unwrap(), InitResponse::default());

    let config = ReadonlyConfig::from_storage(&deps.storage);
    let constants = config.constants().unwrap();
    assert_eq!(config.total_supply(), 5000);
    assert_eq!(config.contract_status(), ContractStatusLevel::NormalRun);
    assert_eq!(constants.name, "sec-sec".to_string());
    assert_eq!(constants.admin, HumanAddr("admin".to_string()));
    assert_eq!(constants.symbol, "SECSEC".to_string());
    assert_eq!(constants.decimals, 8);
    assert_eq!(
        constants.prng_seed,
        sha_256("lolz fun yay".to_owned().as_bytes())
    );
    assert_eq!(constants.total_supply_is_public, false);
}

#[test]
fn test_total_supply_overflow() {
    let (init_result, _deps) = init_helper(vec![InitialBalance {
        address: HumanAddr("lebron".to_string()),
        amount: Uint128(u128::max_value()),
    }]);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let (init_result, _deps) = init_helper(vec![
        InitialBalance {
            address: HumanAddr("lebron".to_string()),
            amount: Uint128(u128::max_value()),
        },
        InitialBalance {
            address: HumanAddr("giannis".to_string()),
            amount: Uint128(1),
        },
    ]);
    let error = extract_error_msg(init_result);
    assert_eq!(
        error,
        "The sum of all initial balances exceeds the maximum possible total supply"
    );
}

