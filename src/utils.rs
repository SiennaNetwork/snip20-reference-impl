use cosmwasm_std::{StdResult, HandleResponse};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use subtle::ConstantTimeEq;

use crate::viewing_key::VIEWING_KEY_SIZE;

pub fn ct_slice_compare(s1: &[u8], s2: &[u8]) -> bool {
    bool::from(s1.ct_eq(s2))
}

pub fn create_hashed_password(s1: &str) -> [u8; VIEWING_KEY_SIZE] {
    Sha256::digest(s1.as_bytes())
        .as_slice()
        .try_into()
        .expect("Wrong password length")
}

// Take a Vec<u8> and pad it up to a multiple of `block_size`, using spaces at the end.
pub fn space_pad(message: &mut Vec<u8>, block_size: usize,) -> &mut Vec<u8> {
    let len = message.len();
    let surplus = len % block_size;
    if surplus == 0 {
        return message;
    }

    let missing = block_size - surplus;
    message.reserve(missing);
    message.extend(std::iter::repeat(b' ').take(missing));
    message
}

pub fn pad_response(response: StdResult<HandleResponse>, block_size: usize) -> StdResult<HandleResponse> {
    response.map(|mut response| {
        response.data = response.data.map(|mut data| {
            space_pad(&mut data.0, block_size);
            data
        });
        response
    })
}