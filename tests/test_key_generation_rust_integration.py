import fast_stark_crypto


def test_well_known_keypair_generation() -> None:
    (priv, pub) = fast_stark_crypto.generate_keypair_from_eth_signature(
        eth_signature="0x9ef64d5936681edf44b4a7ad713f3bc24065d4039562af03fccf6a08d6996eab367df11439169b417b6a6d8ce81d409edb022597ce193916757c7d5d9cbf97301c"
    )

    assert priv == int("0x7dbb2c8651cc40e1d0d60b45eb52039f317a8aa82798bda52eee272136c0c44", 16)
    assert pub == int("0x78298687996aff29a0bbcb994e1305db082d084f85ec38bb78c41e6787740ec", 16)
