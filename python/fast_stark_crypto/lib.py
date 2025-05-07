from fast_stark_crypto.fast_stark_crypto import (
    rs_get_public_key,
    rs_compute_pedersen_hash,
    rs_sign_message,
    rs_verify_signature,
    rs_get_order_msg,
    rs_get_transfer_msg,
    rs_generate_keypair_from_eth_signature,
)


def get_public_key(private_key: int) -> int:
    return int(rs_get_public_key(hex(private_key)))


def pedersen_hash(first: int, second: int) -> int:
    return int(rs_compute_pedersen_hash(hex(first), hex(second)))

def sign(private_key: int, msg_hash: int) -> tuple[int, int]:
    (r, s) = rs_sign_message(hex(private_key), hex(msg_hash))
    return (int(r), int(s))


def verify(public_key: int, msg_hash: int, r: int, s: int) -> bool:
    return bool(rs_verify_signature(hex(public_key), hex(msg_hash), hex(r), hex(s)) == True)

def generate_keypair_from_eth_signature(
    eth_signature: str,
) -> tuple[int, int]:
    (priv, pub) = rs_generate_keypair_from_eth_signature(eth_signature)
    return (int(priv, 16), int(pub, 16))


def get_order_msg_hash(
    position_id: int,
    base_asset_id: int,
    base_amount: int,
    quote_asset_id: int,
    quote_amount: int,
    fee_asset_id: int,
    fee_amount: int,
    expiration: int,
    salt: int,
    user_public_key: int,
    domain_name: str,
    domain_version: str,
    domain_chain_id: str,
    domain_revision: str,
) -> int:
    return int(
        rs_get_order_msg(
            str(position_id),
            hex(base_asset_id),
            str(base_amount),
            hex(quote_asset_id),
            str(quote_amount),
            hex(fee_asset_id),
            str(fee_amount),
            str(expiration),
            str(salt),
            hex(user_public_key),
            domain_name,
            domain_version,
            domain_chain_id,
            domain_revision,
        ),
        16,
    )


def get_transfer_msg_hash(
    recipient_position_id: int,
    sender_position_id: int,
    collateral_id: int,
    amount: int,
    expiration: int,
    salt: int,
    user_public_key: int,
    domain_name: str,
    domain_version: str,
    domain_chain_id: str,
    domain_revision: str,
) -> int:
    return int(
        rs_get_transfer_msg(
            str(recipient_position_id),
            str(sender_position_id),
            hex(collateral_id),
            str(amount),
            str(expiration),
            str(salt),
            hex(user_public_key),
            domain_name,
            domain_version,
            domain_chain_id,
            domain_revision,
        ),
        16,
    )
