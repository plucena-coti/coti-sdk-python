import pytest
import os
from eth_keys import keys
from coti.crypto_utils import generate_aes_key

@pytest.fixture
def user_key():
    # Return hex string of the key
    return os.environ.get("TEST_USER_KEY") or generate_aes_key().hex()

@pytest.fixture
def private_key_bytes():
    pk_hex = os.environ.get("TEST_PRIVATE_KEY")
    if pk_hex:
        # Handle 0x prefix if present
        clean_hex = pk_hex[2:] if pk_hex.startswith("0x") else pk_hex
        return bytes.fromhex(clean_hex)
    return os.urandom(32)

@pytest.fixture
def sender_address(private_key_bytes):
    # Derive address from private key to ensure consistency in signing checks if needed
    pk = keys.PrivateKey(private_key_bytes)
    return pk.public_key.to_checksum_address()

@pytest.fixture
def contract_address():
    # Dummy contract address
    return "0x1000000000000000000000000000000000000001"

@pytest.fixture
def function_selector():
    # Dummy function selector
    return "0x11223344"
