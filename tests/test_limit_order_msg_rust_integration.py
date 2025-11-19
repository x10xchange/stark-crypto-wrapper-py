from fast_stark_crypto.lib import get_limit_order_msg_hash


def test_limit_order_msg_hash():
    expected_hash = int(
        "0x396b726a20930d4b4e1a15d3a96aaf3952d788d324a68e1ef06999e7c0fcc97", 16)

    result = get_limit_order_msg_hash(
        source_position_id=1,
        receive_position_id=2,
        base_asset_id=2,
        base_amount=3,
        quote_asset_id=4,
        quote_amount=5,
        fee_asset_id=6,
        fee_amount=7,
        expiration=8,
        salt=9,
        user_public_key=int(
            "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904", 16),
        domain_name="Perpetuals",
        domain_version="v0",
        domain_chain_id="SN_SEPOLIA",
        domain_revision="1",
    )
    assert result == expected_hash, f"Expected {hex(expected_hash)}, got {hex(result)}"
