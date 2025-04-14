use malachite::{num::conversion::traits::FromStringBase, strings::ToLowerHexString, Integer};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use starknet_crypto::{
    get_public_key as fetch_public_key, pedersen_hash, sign, verify as verify_signature, Felt,
};
use starknet_messages::{AssetId, OffChainMessage, Order, PositionId, StarknetDomain, Timestamp};

mod messages;
mod starknet_messages;

// Converts a hexadecimal string to a FieldElement
fn str_to_field_element(hex_str: &str) -> Result<Felt, String> {
    Felt::from_hex(hex_str).map_err(|e| {
        format!(
            "Failed to convert hex string {} to FieldElement: {}",
            hex_str, e
        )
    })
}

fn int_to_field_element(int: &Integer) -> Result<Felt, String> {
    str_to_field_element(&int.to_lower_hex_string())
}

#[pyfunction]
fn rs_get_public_key(py: Python, private_key_hex: String) -> PyResult<String> {
    py.allow_threads(move || {
        str_to_field_element(&private_key_hex)
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
            .and_then(|private_key| Ok(fetch_public_key(&private_key).to_string()))
    })
}

#[pyfunction]
fn rs_compute_pedersen_hash(py: Python, left_hex: String, right_hex: String) -> PyResult<String> {
    py.allow_threads(move || {
        str_to_field_element(&left_hex)
            .and_then(|left| {
                str_to_field_element(&right_hex)
                    .map_err(|e| e.into())
                    .and_then(|right| Ok(pedersen_hash(&left, &right).to_string()))
            })
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
    })
}

#[pyfunction]
fn rs_sign_message(
    py: Python,
    priv_key_hex: String,
    msg_hash_hex: String,
    k_hex: String,
) -> PyResult<(String, String)> {
    py.allow_threads(move || {
        str_to_field_element(&priv_key_hex)
            .and_then(|priv_key| {
                str_to_field_element(&msg_hash_hex).and_then(|msg_hash| {
                    str_to_field_element(&k_hex).and_then(|k| {
                        sign(&priv_key, &msg_hash, &k)
                            .map(|signature| (signature.r.to_string(), signature.s.to_string()))
                            .map_err(|e| format!("Signing operation failed: {}", e))
                    })
                })
            })
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
    })
}

#[pyfunction]
fn rs_verify_signature(
    py: Python,
    public_key_hex: String,
    msg_hash_hex: String,
    r_hex: String,
    s_hex: String,
) -> PyResult<bool> {
    py.allow_threads(move || {
        str_to_field_element(&public_key_hex)
            .and_then(|public_key| {
                str_to_field_element(&msg_hash_hex).and_then(|msg_hash| {
                    str_to_field_element(&r_hex).and_then(|r| {
                        str_to_field_element(&s_hex).and_then(|s| {
                            Ok(verify_signature(&public_key, &msg_hash, &r, &s).unwrap())
                        })
                    })
                })
            })
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
    })
}

#[pyfunction]
fn rs_get_order_msg(
    py: Python,
    position_id: String,
    base_asset_id_hex: String,
    base_amount: String,
    quote_asset_id_hex: String,
    quote_amount: String,
    fee_asset_id_hex: String,
    fee_amount: String,
    expiration: String,
    salt: String,
    user_public_key_hex: String,

    domain_name: String,
    domain_version: String,
    domain_chain_id: String,
    domain_revision: String,
) -> PyResult<String> {
    py.allow_threads(move || {
        //hex fields
        let base_asset_id = Felt::from_hex(&base_asset_id_hex).unwrap();
        let quote_asset_id = Felt::from_hex(&quote_asset_id_hex).unwrap();
        let fee_asset_id = Felt::from_hex(&fee_asset_id_hex).unwrap();
        let user_key = Felt::from_hex(&user_public_key_hex).unwrap();

        //decimal fields
        let position_id = u32::from_str_radix(&position_id, 10).unwrap();
        let base_amount = i64::from_str_radix(&base_amount, 10).unwrap();
        let quote_amount = i64::from_str_radix(&quote_amount, 10).unwrap();
        let fee_amount = u64::from_str_radix(&fee_amount, 10).unwrap();
        let expiration = u64::from_str_radix(&expiration, 10).unwrap();
        let salt = u64::from_str_radix(&salt, 10).unwrap();

        let order = Order {
            position_id: PositionId { value: position_id },
            base_asset_id: AssetId {
                value: base_asset_id,
            },
            base_amount: base_amount,
            quote_asset_id: AssetId {
                value: quote_asset_id,
            },
            quote_amount: quote_amount,
            fee_asset_id: AssetId {
                value: fee_asset_id,
            },
            fee_amount: fee_amount,
            expiration: Timestamp {
                seconds: expiration,
            },
            salt: salt.try_into().unwrap(),
        };
        let domain = StarknetDomain {
            name: domain_name,
            version: domain_version,
            chain_id: domain_chain_id,
            revision: domain_revision,
        };
        let message = order.message_hash(&domain, user_key).unwrap();
        Ok(message.to_hex_string())
    })
}

#[pymodule]
fn fast_stark_crypto(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(rs_get_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(rs_compute_pedersen_hash, m)?)?;
    m.add_function(wrap_pyfunction!(rs_sign_message, m)?)?;
    m.add_function(wrap_pyfunction!(rs_verify_signature, m)?)?;
    m.add_function(wrap_pyfunction!(rs_get_order_msg, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use pyo3::types::PyTuple;

    use super::*;

    #[test]
    fn test_rs_get_order_msg() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let module = PyModule::new(py, "fast_stark_crypto").unwrap();
            fast_stark_crypto(py, module).unwrap();
            let position_id = "100".to_string();
            let base_asset_id = "0x2".to_string();
            let base_amount = "100".to_string();
            let quote_asset_id = "0x1".to_string();
            let quote_amount = "-156".to_string();
            let fee_asset_id = "0x1".to_string();
            let fee_amount = "74".to_string();
            let expiration = "100".to_string();
            let salt = "123".to_string();
            let user_public_key =
                "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string();
            let domain_name = "Perpetuals".to_string();
            let domain_version = "v0".to_string();
            let domain_chain_id = "SN_SEPOLIA".to_string();
            let domain_revision = "1".to_string();
            let result: String = module
                .getattr("rs_get_order_msg")
                .unwrap()
                .call1(PyTuple::new(
                    py,
                    [
                        position_id,
                        base_asset_id,
                        base_amount,
                        quote_asset_id,
                        quote_amount,
                        fee_asset_id,
                        fee_amount,
                        expiration,
                        salt,
                        user_public_key,
                        domain_name,
                        domain_version,
                        domain_chain_id,
                        domain_revision,
                    ],
                ))
                .unwrap()
                .extract()
                .unwrap();

            assert_eq!(
                result,
                "0x62428944e2c935c4c6662ec0328abfcab44dd6455cb48845c78d18f0ea0450b"
            );
        });
    }
}
