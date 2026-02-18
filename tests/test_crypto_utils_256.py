
from coti.crypto_utils import (
    build_input_text, decrypt_uint, prepare_it_256, decrypt_uint256, 
    generate_aes_key, sign_input_text_256
)
import pytest
import os

# Mock keys usually 32 bytes hex
MOCK_AES_KEY = generate_aes_key().hex()
MOCK_SENDER = "0x" + "1" * 40
MOCK_CONTRACT = "0x" + "2" * 40
MOCK_SELECTOR = "0x12345678"
# Using a dummy signing key (private key) - we can use an account from brownie or generate one
# For simple unit testing of crypto logic without full eth keys lib dependency, we might need to mock signature
# But crypto_utils imports 'keys' from 'eth_keys'.
# Let's try to use a dummy 32-byte key for signing
MOCK_SIGNING_KEY = os.urandom(32)


def test_encryption_decryption_256():
    # Test with a value > 128 bits
    plaintext_256 = (1 << 240) + 123456789
    
    # Prepare IT (Encrypt)
    # We use a mocked signing key, actual signature validity doesn't matter for decrypt unit test
    it = prepare_it_256(
        plaintext_256, 
        MOCK_AES_KEY, 
        MOCK_SENDER, 
        MOCK_CONTRACT, 
        MOCK_SELECTOR, 
        MOCK_SIGNING_KEY
    )
    
    # Check structure
    assert 'ciphertext' in it
    assert 'ciphertextHigh' in it['ciphertext']
    assert 'ciphertextLow' in it['ciphertext']
    assert 'signature' in it
    
    # Decrypt
    decrypted_val = decrypt_uint256(it['ciphertext'], MOCK_AES_KEY)
    
    assert decrypted_val == plaintext_256


def test_encryption_decryption_256_small_value():
    # Test with a small value fitting in 128 bits, but using 256 pipeline
    plaintext_small = 42
    
    it = prepare_it_256(
        plaintext_small, 
        MOCK_AES_KEY, 
        MOCK_SENDER, 
        MOCK_CONTRACT, 
        MOCK_SELECTOR, 
        MOCK_SIGNING_KEY
    )
    
    decrypted_val = decrypt_uint256(it['ciphertext'], MOCK_AES_KEY)
    
    assert decrypted_val == plaintext_small


def test_overflow_check():
    # Test value > 256 bits
    plaintext_large = 1 << 257
    
    with pytest.raises(ValueError):
        prepare_it_256(
            plaintext_large, 
            MOCK_AES_KEY, 
            MOCK_SENDER, 
            MOCK_CONTRACT, 
            MOCK_SELECTOR, 
            MOCK_SIGNING_KEY
        )


def test_max_256_bit_value():
    """Test with exactly 256-bit value (2^256 - 1)"""
    plaintext_max = (1 << 256) - 1
    
    it = prepare_it_256(
        plaintext_max, 
        MOCK_AES_KEY, 
        MOCK_SENDER, 
        MOCK_CONTRACT, 
        MOCK_SELECTOR, 
        MOCK_SIGNING_KEY
    )
    
    decrypted_val = decrypt_uint256(it['ciphertext'], MOCK_AES_KEY)
    
    assert decrypted_val == plaintext_max


def test_various_bit_lengths():
    """Test round-trip with various bit lengths (129-bit, 200-bit, 255-bit)"""
    test_values = [
        (1 << 128) + 1,  # 129-bit value
        (1 << 199) + 12345,  # 200-bit value
        (1 << 254) + 9876543210,  # 255-bit value
    ]
    
    for plaintext in test_values:
        it = prepare_it_256(
            plaintext, 
            MOCK_AES_KEY, 
            MOCK_SENDER, 
            MOCK_CONTRACT, 
            MOCK_SELECTOR, 
            MOCK_SIGNING_KEY
        )
        
        decrypted_val = decrypt_uint256(it['ciphertext'], MOCK_AES_KEY)
        assert decrypted_val == plaintext, f"Failed for {plaintext.bit_length()}-bit value"


def test_sign_input_text_256_invalid_sender_address():
    """Test sign_input_text_256 with invalid sender address length"""
    ct_blob = b'0' * 64
    
    # Invalid sender address (19 bytes instead of 20)
    invalid_sender = b'1' * 19
    valid_contract = b'2' * 20
    
    with pytest.raises(ValueError, match="Invalid sender address length"):
        sign_input_text_256(
            invalid_sender,
            valid_contract,
            MOCK_SELECTOR,
            ct_blob,
            MOCK_SIGNING_KEY
        )


def test_sign_input_text_256_invalid_contract_address():
    """Test sign_input_text_256 with invalid contract address length"""
    ct_blob = b'0' * 64
    
    valid_sender = b'1' * 20
    invalid_contract = b'2' * 21  # 21 bytes instead of 20
    
    with pytest.raises(ValueError, match="Invalid contract address length"):
        sign_input_text_256(
            valid_sender,
            invalid_contract,
            MOCK_SELECTOR,
            ct_blob,
            MOCK_SIGNING_KEY
        )


def test_sign_input_text_256_invalid_ct_length():
    """Test sign_input_text_256 with invalid ciphertext length"""
    ct_blob = b'0' * 32  # 32 bytes instead of 64
    
    valid_sender = b'1' * 20
    valid_contract = b'2' * 20
    
    with pytest.raises(ValueError, match="Invalid ct length.*must be 64 bytes"):
        sign_input_text_256(
            valid_sender,
            valid_contract,
            MOCK_SELECTOR,
            ct_blob,
            MOCK_SIGNING_KEY
        )


def test_sign_input_text_256_invalid_key_length():
    """Test sign_input_text_256 with invalid signing key length"""
    ct_blob = b'0' * 64
    
    valid_sender = b'1' * 20
    valid_contract = b'2' * 20
    invalid_key = os.urandom(31)  # 31 bytes instead of 32
    
    with pytest.raises(ValueError, match="Invalid key length"):
        sign_input_text_256(
            valid_sender,
            valid_contract,
            MOCK_SELECTOR,
            ct_blob,
            invalid_key
        )


def test_boundary_values():
    """Test boundary values around 128-bit threshold"""
    boundary_values = [
        (1 << 128) - 1,  # Max 128-bit value
        1 << 128,        # Min 129-bit value (boundary)
        0,               # Zero
        1,               # One
    ]
    
    for plaintext in boundary_values:
        it = prepare_it_256(
            plaintext, 
            MOCK_AES_KEY, 
            MOCK_SENDER, 
            MOCK_CONTRACT, 
            MOCK_SELECTOR, 
            MOCK_SIGNING_KEY
        )
        
        decrypted_val = decrypt_uint256(it['ciphertext'], MOCK_AES_KEY)
        assert decrypted_val == plaintext


def test_high_low_split():
    """Test that high and low parts are correctly split and combined"""
    # Value where high part is non-zero and low part is non-zero
    high_value = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF  # Max 128-bit value
    low_value = 0x123456789ABCDEF0123456789ABCDEF0   # Another 128-bit value
    
    # Combine: high_value << 128 | low_value
    plaintext = (high_value << 128) | low_value
    
    it = prepare_it_256(
        plaintext, 
        MOCK_AES_KEY, 
        MOCK_SENDER, 
        MOCK_CONTRACT, 
        MOCK_SELECTOR, 
        MOCK_SIGNING_KEY
    )
    
    decrypted_val = decrypt_uint256(it['ciphertext'], MOCK_AES_KEY)
    assert decrypted_val == plaintext
    
    # Verify the split is correct by checking bit patterns
    decrypted_high = decrypted_val >> 128
    decrypted_low = decrypted_val & ((1 << 128) - 1)
    
    assert decrypted_high == high_value
    assert decrypted_low == low_value

