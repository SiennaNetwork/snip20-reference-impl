#![cfg(test)]
pub use snip20_reference_impl::{contract::*, msg::*, state::*, receiver::*, viewing_key::*, rand::*};
pub use cosmwasm_std::{
    testing::*,
    from_binary, to_binary, Binary,
    HumanAddr, Uint128,
    Env, BlockInfo, ContractInfo, MessageInfo,
    Extern, Api, Storage, Querier,
    InitResponse, QueryResponse, HandleResponse, WasmMsg, CosmosMsg,
    StdResult, StdError,
};
pub use std::any::Any;

// Helper functions

pub fn init_helper(
    initial_balances: Vec<InitialBalance>,
) -> (
    StdResult<InitResponse>,
    Extern<MockStorage, MockApi, MockQuerier>,
) {
    let mut deps = mock_dependencies(20, &[]);
    let env = mock_env("instantiator", &[]);

    let init_msg = InitMsg {
        name: "sec-sec".to_string(),
        admin: Some(HumanAddr("admin".to_string())),
        symbol: "SECSEC".to_string(),
        decimals: 8,
        initial_balances: Some(initial_balances),
        prng_seed: Binary::from("lolz fun yay".as_bytes()),
        config: None,
    };

    (init(&mut deps, env, init_msg), deps)
}

pub fn extract_error_msg<T: Any>(error: StdResult<T>) -> String {
    match error {
        Ok(response) => {
            let bin_err = (&response as &dyn Any)
                .downcast_ref::<QueryResponse>()
                .expect("An error was expected, but no error could be extracted");
            match from_binary(bin_err).unwrap() {
                QueryAnswer::ViewingKeyError { msg } => msg,
                _ => panic!("Unexpected query answer"),
            }
        }
        Err(err) => match err {
            StdError::GenericErr { msg, .. } => msg,
            _ => panic!("Unexpected result from init"),
        },
    }
}

pub fn ensure_success(handle_result: HandleResponse) -> bool {
    let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

    match handle_result {
        HandleAnswer::Deposit { status }
        | HandleAnswer::Redeem { status }
        | HandleAnswer::Transfer { status }
        | HandleAnswer::Send { status }
        | HandleAnswer::Burn { status }
        | HandleAnswer::RegisterReceive { status }
        | HandleAnswer::SetViewingKey { status }
        | HandleAnswer::TransferFrom { status }
        | HandleAnswer::SendFrom { status }
        | HandleAnswer::BurnFrom { status }
        | HandleAnswer::Mint { status }
        | HandleAnswer::ChangeAdmin { status }
        | HandleAnswer::SetContractStatus { status }
        | HandleAnswer::SetMinters { status }
        | HandleAnswer::AddMinters { status }
        | HandleAnswer::RemoveMinters { status } => {
            matches!(status, ResponseStatus::Success {..})
        }
        _ => panic!("HandleAnswer not supported for success extraction"),
    }
}
