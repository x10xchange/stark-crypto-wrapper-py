import fast_stark_crypto


def test_well_known_order_hash() -> None:
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

    assert hash_from_rust == int("0x4de4c009e0d0c5a70a7da0e2039fb2b99f376d53496f89d9f437e736add6b48", 16)


def test_sdk_buy_order_value() -> None:
    synth_id = "0x4254432d3600000000000000000000"
    collateral_id = "0x31857064564ed0ff978e687456963cba09c2c6985d8f9300a1de4962fafa054"
    fee_id = collateral_id
    fee_amount = 21723
    base_amount = 1000
    collateral_amount = -43445117
    hash_from_rust = fast_stark_crypto.get_order_msg_hash(
        position_id=10002,
        base_asset_id=int(synth_id, 16),
        base_amount=base_amount,
        quote_asset_id=int(collateral_id, 16),
        quote_amount=collateral_amount,
        fee_asset_id=int(fee_id, 16),
        fee_amount=fee_amount,
        expiration=1706836137,
        salt=1473459052,
        user_public_key=int("0x61c5e7e8339b7d56f197f54ea91b776776690e3232313de0f2ecbd0ef76f466", 16),
        domain_name="Perpetuals",
        domain_version="v0",
        domain_chain_id="SN_SEPOLIA",
        domain_revision="1",
    )

    assert hash_from_rust == int("0x58454e78c25644cbcab59444736d573f169fb0996dafe1900a05e2ac50567f0", 16)
