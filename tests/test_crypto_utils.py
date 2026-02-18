from coti.crypto_utils import (
    encrypt, decrypt, build_input_text, build_string_input_text, 
    decrypt_uint, decrypt_string, block_size
)
from Crypto.Random import get_random_bytes
import pytest

def test_encrypt_decrypt_basic(user_key):
    # Test basic encryption and decryption
    user_key_bytes = bytes.fromhex(user_key)
    plaintext = b"0" * 15 + b"1" # 16 bytes
    
    ciphertext, r = encrypt(user_key_bytes, plaintext)
    
    assert len(ciphertext) == block_size
    assert len(r) == block_size
    
    decrypted = decrypt(user_key_bytes, r, ciphertext)
    assert decrypted == plaintext

def test_encrypt_invalid_plaintext_size(user_key):
    user_key_bytes = bytes.fromhex(user_key)
    plaintext = b"0" * 17 # 17 bytes
    
    with pytest.raises(ValueError, match="Plaintext size must be 128 bits or smaller"):
        encrypt(user_key_bytes, plaintext)

def test_encrypt_invalid_key_size():
    user_key_bytes = get_random_bytes(15) # 15 bytes
    plaintext = b"0" * 16
    
    with pytest.raises(ValueError, match="Key size must be 128 bits"):
        encrypt(user_key_bytes, plaintext)

def test_decrypt_invalid_ciphertext_size(user_key):
    user_key_bytes = bytes.fromhex(user_key)
    r = get_random_bytes(16)
    ciphertext = b"0" * 15
    
    with pytest.raises(ValueError, match="Ciphertext size must be 128 bits"):
        decrypt(user_key_bytes, r, ciphertext)

def test_build_input_text_128(user_key, sender_address, contract_address, function_selector, private_key_bytes):
    # Test 128-bit UINT Input Text
    plaintext = 123456789
    
    it = build_input_text(
        plaintext,
        user_key,
        sender_address,
        contract_address,
        function_selector,
        private_key_bytes
    )
    
    assert 'ciphertext' in it
    assert 'signature' in it
    assert isinstance(it['ciphertext'], int)
    
    # Decrypt to verify
    decrypted = decrypt_uint(it['ciphertext'], user_key)
    assert decrypted == plaintext

def test_build_input_text_max_128(user_key, sender_address, contract_address, function_selector, private_key_bytes):
    # Test max 128-bit value
    plaintext = (1 << 128) - 1
    
    it = build_input_text(
        plaintext,
        user_key,
        sender_address,
        contract_address,
        function_selector,
        private_key_bytes
    )
    
    decrypted = decrypt_uint(it['ciphertext'], user_key)
    assert decrypted == plaintext

def test_build_string_input_text_basic(user_key, sender_address, contract_address, function_selector, private_key_bytes):
    plaintext = "Hello, World!"
    
    it = build_string_input_text(
        plaintext, 
        user_key,
        sender_address,
        contract_address,
        function_selector,
        private_key_bytes
    )
    
    assert 'ciphertext' in it
    assert 'value' in it['ciphertext']
    assert isinstance(it['ciphertext']['value'], list)
    assert len(it['ciphertext']['value']) > 0
    
    # Decrypt
    decrypted = decrypt_string(it['ciphertext'], user_key)
    assert decrypted == plaintext

def test_build_string_input_text_empty(user_key, sender_address, contract_address, function_selector, private_key_bytes):
    plaintext = ""
    it = build_string_input_text(
        plaintext,
        user_key,
        sender_address,
        contract_address,
        function_selector,
        private_key_bytes
    )
    
    assert len(it['ciphertext']['value']) == 0
    
    decrypted = decrypt_string(it['ciphertext'], user_key)
    assert decrypted == plaintext

def test_build_string_input_text_long(user_key, sender_address, contract_address, function_selector, private_key_bytes):
    # Long string that spans multiple blocks
    plaintext = "A" * 100
    
    it = build_string_input_text(
        plaintext,
        user_key,
        sender_address,
        contract_address,
        function_selector,
        private_key_bytes
    )
    
    # 100 bytes / 8 bytes per chunk = 13 chunks (12 full, 1 partial)
    assert len(it['ciphertext']['value']) == 13
    
    decrypted = decrypt_string(it['ciphertext'], user_key)
    assert decrypted == plaintext
