//! Support for the [CreateX](https://github.com/pcaversaccio/createx) factory as the CREATE2
//! deployer.
//!
//! When the configured CREATE2 deployer holds CreateX's runtime code, salted deployments call
//! `deployCreate2(bytes32,bytes)` on it instead of sending `salt ++ initCode` as Nick's factory
//! expects. CreateX derives the CREATE2 salt from the given one ("guarded salt"), so addresses
//! differ from Nick's factory for the same salt.

use alloy_primitives::{Address, B256, Bytes, U256, address, b256, hex, keccak256};
use alloy_sol_types::{SolCall, SolValue, sol};
use std::sync::LazyLock;

/// The address of CreateX on every chain where it is deployed.
pub const CREATEX_ADDRESS: Address = address!("0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed");

/// The hash of CreateX's runtime code at [`CREATEX_ADDRESS`].
pub const CREATEX_CODEHASH: B256 =
    b256!("0xbd8a7ea8cfca7b4e5f5041d7d4b17bc317c5ce42cfbc42066a00cf26b43eb53f");

/// CreateX's runtime code at [`CREATEX_ADDRESS`], for local tests and scripts without a fork.
pub static CREATEX_RUNTIME_CODE: LazyLock<Bytes> = LazyLock::new(|| {
    hex::decode(include_str!("createx_runtime.hex").trim())
        .expect("valid CreateX runtime hex")
        .into()
});

sol! {
    function deployCreate2(bytes32 salt, bytes initCode) external payable returns (address newContract);
}

/// Returns the calldata of `deployCreate2(salt, initCode)`.
pub fn deploy_create2_calldata(salt: B256, init_code: &[u8]) -> Bytes {
    deployCreate2Call { salt, initCode: Bytes::copy_from_slice(init_code) }.abi_encode().into()
}

/// Decodes `deployCreate2(salt, initCode)` calldata.
pub fn decode_deploy_create2(input: &[u8]) -> Option<(B256, Bytes)> {
    let call = deployCreate2Call::abi_decode(input).ok()?;
    Some((call.salt, call.initCode))
}

/// Returns the salt CreateX passes to CREATE2 when `sender` calls it with `salt` on `chain_id`,
/// or `None` where CreateX reverts with `InvalidSalt`.
///
/// Mirrors `CreateX._guard`. The case where `salt` equals CreateX's block-derived pseudo-random
/// salt is not modelled; a caller cannot choose it in advance.
pub fn guarded_salt(sender: Address, chain_id: u64, salt: B256) -> Option<B256> {
    let prefix = Address::from_slice(&salt[..20]);
    let flag = salt[20];
    let chain = U256::from(chain_id);
    if prefix == sender {
        match flag {
            0x01 => Some(keccak256((sender, chain, salt).abi_encode())),
            0x00 => Some(keccak256([B256::left_padding_from(sender.as_slice()), salt].concat())),
            _ => None,
        }
    } else if prefix == Address::ZERO && flag == 0x01 {
        Some(keccak256([B256::from(chain), salt].concat()))
    } else if prefix == Address::ZERO && flag != 0x00 {
        None
    } else {
        Some(keccak256(salt.abi_encode()))
    }
}

/// Returns the address CreateX at `factory` deploys `init_code` to.
pub fn create2_address(
    factory: Address,
    sender: Address,
    chain_id: u64,
    salt: B256,
    init_code: &[u8],
) -> Option<Address> {
    Some(factory.create2_from_code(guarded_salt(sender, chain_id, salt)?, init_code))
}

/// Returns the salt to link libraries with, and the salt to send in `deployCreate2` when
/// `deployer` is CreateX.
///
/// Library addresses are `deployer.create2_from_code(link_salt, code)` for both factories; with
/// CreateX, `link_salt` is the guarded salt of `salt`.
pub fn library_salts(
    deployer: Address,
    sender: Address,
    chain_id: u64,
    salt: B256,
) -> eyre::Result<(B256, Option<B256>)> {
    if deployer != CREATEX_ADDRESS {
        return Ok((salt, None));
    }
    let guarded = guarded_salt(sender, chain_id, salt).ok_or_else(|| {
        eyre::eyre!(
            "`create2_library_salt` {salt} is rejected by CreateX (InvalidSalt): byte 21 must be \
             0x00 or 0x01 when the first 20 bytes are the sender or zero"
        )
    })?;
    Ok((guarded, Some(salt)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_code_matches_codehash() {
        assert_eq!(keccak256(CREATEX_RUNTIME_CODE.as_ref()), CREATEX_CODEHASH);
    }

    #[test]
    fn calldata_round_trips() {
        let salt = B256::with_last_byte(7);
        let data = deploy_create2_calldata(salt, &[0x60, 0x00]);
        assert_eq!(&data[..4], &hex!("26307668"));
        assert_eq!(decode_deploy_create2(&data), Some((salt, Bytes::from_static(&[0x60, 0x00]))));
    }

    #[test]
    fn guarded_salt_cases() {
        let sender = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let other = address!("0x70997970C51812dc3A010C7d01b50e9d17dc79C8");
        let with = |prefix: Address, flag: u8| {
            let mut salt = B256::repeat_byte(0xab);
            salt[..20].copy_from_slice(prefix.as_slice());
            salt[20] = flag;
            salt
        };

        // Sender-bound, cross-chain protected: depends on sender and chain.
        let s = with(sender, 1);
        assert_eq!(
            guarded_salt(sender, 1, s),
            Some(keccak256((sender, U256::from(1), s).abi_encode()))
        );
        assert_ne!(guarded_salt(sender, 1, s), guarded_salt(sender, 10, s));
        // Sender-bound only: same on every chain.
        assert_eq!(
            guarded_salt(sender, 1, with(sender, 0)),
            guarded_salt(sender, 10, with(sender, 0))
        );
        // Explicit flag required.
        assert_eq!(guarded_salt(sender, 1, with(sender, 2)), None);
        assert_eq!(guarded_salt(sender, 1, with(Address::ZERO, 2)), None);
        // Zero prefix with protection: chain-bound, sender-free.
        assert_eq!(
            guarded_salt(sender, 5, with(Address::ZERO, 1)),
            guarded_salt(other, 5, with(Address::ZERO, 1))
        );
        // Anything else is hashed and independent of sender and chain.
        let plain = B256::from(U256::from(0xC0FFEE));
        assert_eq!(guarded_salt(sender, 1, plain), Some(keccak256(plain.abi_encode())));
        assert_eq!(guarded_salt(sender, 1, plain), guarded_salt(other, 10, plain));
    }
}
