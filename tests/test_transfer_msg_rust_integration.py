import fast_stark_crypto


def test_well_known_transfer_hash() -> None:
    expected_hash = int("2453233552426028319905576552240018623512915507691922332978444357299842334607")
    actual_hash = fast_stark_crypto.get_transfer_msg_hash(
        recipient_position_id=1,
        sender_position_id=2,
        collateral_id=3,
        amount=4,
        expiration=5,
        salt=6,
        user_public_key=int("2629686405885377265612250192330550814166101744721025672593857097107510831364"),
        domain_name="Perpetuals",
        domain_version="v0",
        domain_chain_id="SN_SEPOLIA",
        domain_revision="1",
    )
    assert actual_hash == expected_hash, "Hashes do not match for get_transfer_msg_hash"
