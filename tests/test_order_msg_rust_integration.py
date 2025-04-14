import fast_stark_crypto


def test_well_known_order_hash():
    hash_from_rust = fast_stark_crypto.get_order_msg_hash(
        position_id=100,
        base_asset_id=2,
        base_amount=100,
        quote_asset_id=1,
        quote_amount=-156,
        fee_asset_id=1,
        fee_amount=74,
        expiration=100,
        salt=123,
        user_public_key=int("0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904", 16),
        domain_name="Perpetuals",
        domain_version="v0",
        domain_chain_id="SN_SEPOLIA",
        domain_revision="1",
    )

    assert hash_from_rust == int("0x62428944e2c935c4c6662ec0328abfcab44dd6455cb48845c78d18f0ea0450b", 16)
