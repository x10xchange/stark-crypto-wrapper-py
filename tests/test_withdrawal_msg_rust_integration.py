import fast_stark_crypto


def test_well_known_withdrawal_hash() -> None:
    expected_hash = int("2182119571682827544073774098906745929330860211691330979324731407862023927178")
    actual_hash = fast_stark_crypto.get_withdrawal_msg_hash(
        recipient_hex=hex(206642948138484946401984817000601902748248360221625950604253680558965863254),
        position_id=2,
        collateral_id=int("1386727789535574059419576650469753513512158569780862144831829362722992755422"),
        amount=1000,
        expiration=0,
        salt=0,
        user_public_key=int("0x5D05989E9302DCEBC74E241001E3E3AC3F4402CCF2F8E6F74B034B07AD6A904", 16),
        domain_name="Perpetuals",
        domain_version="v0",
        domain_chain_id="SN_SEPOLIA",
        domain_revision="1",
    )
    assert actual_hash == expected_hash, "Hashes do not match for get_transfer_msg_hash"
